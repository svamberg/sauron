# Sauron::UtilDhcp.pm - ISC DHCPD config file reading/parsing routines
#
# Copyright (c) Michal Kostenec <kostenec@civ.zcu.cz> 2013-2014.
# Copyright (c) Timo Kokkonen <tjko@iki.fi> 2002.
# $Id:$
#
package Sauron::UtilDhcp;
require Exporter;
use IO::File;
use JSON::PP;
use Net::IP qw(:PROC);
use Sauron::Util;
use strict;
use vars qw($VERSION @ISA @EXPORT);
use open ':locale';

$VERSION = '$Id:$ ';

@ISA = qw(Exporter); # Inherit from Exporter
@EXPORT = qw(process_dhcpdconf process_kea_dhcpconf is_kea_dhcpconf
             build_kea_from_isc_data);


my $debug = 0;

sub _init_data_refs($) {
  my ($data) = @_;

  $$data{GLOBAL} = [] unless (defined $$data{GLOBAL} && ref($$data{GLOBAL}) eq 'ARRAY');
  foreach my $key ('shared-network','subnet','subnet6','group','class','subclass','pool','pool6','host') {
    $$data{$key} = {} unless (defined $$data{$key} && ref($$data{$key}) eq 'HASH');
  }

  return 0;
}

sub _arrayref($) {
  my ($value) = @_;
  return $value if (defined $value && ref($value) eq 'ARRAY');
  return [];
}

sub _normalize_hex_sequence($) {
  my ($value) = @_;

  return '' unless (defined $value);

  if ($value =~ /^[0-9A-Fa-f]+$/ && (length($value) % 2) == 0) {
    my @tmp = ($value =~ /(..)/g);
    return join(':',@tmp);
  }

  return $value;
}

sub _bits_to_netmask($) {
  my ($bits) = @_;
  my @octets;
  my ($full,$rest);

  return '' if (!defined $bits || $bits < 0 || $bits > 32);

  $full = int($bits / 8);
  $rest = $bits % 8;

  for my $i (0..3) {
    my $octet = 0;

    if ($i < $full) {
      $octet = 255;
    }
    elsif ($i == $full && $rest > 0) {
      $octet = (0xFF << (8 - $rest)) & 0xFF;
    }

    push @octets, $octet;
  }

  return join('.',@octets);
}

sub _kea_ipv4_subnet_key($) {
  my ($subnet) = @_;
  my ($ip,$bits,$mask);

  return undef unless (defined $subnet);
  return undef unless ($subnet =~ /^\s*(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})\s*$/);

  ($ip,$bits) = ($1,$2);
  return undef if ($bits < 0 || $bits > 32);

  $mask = _bits_to_netmask($bits);
  return undef unless ($mask);

  return "$ip netmask $mask";
}

sub _kea_option_to_line($) {
  my ($opt) = @_;
  my ($name,$space,$line);

  return undef unless (defined $opt && ref($opt) eq 'HASH');

  $name = $$opt{name};
  return undef unless (defined $name && $name ne '');

  $space = $$opt{space};
  if (defined $space && $space ne '' && $space !~ /^dhcp[46]?$/i) {
    $name = "$space.$name";
  }

  $line = "option $name";
  if (defined $$opt{data} && $$opt{data} ne '') {
    $line .= " $$opt{data}";
  }

  $line .= ';';
  return $line;
}

sub _append_option_data_lines($$) {
  my ($dst,$optdata) = @_;

  return unless (defined $dst && ref($dst) eq 'ARRAY');

  foreach my $opt (@{_arrayref($optdata)}) {
    my $line = _kea_option_to_line($opt);
    push @$dst, $line if (defined $line);
  }
}

sub _kea_pool_bounds($) {
  my ($pool) = @_;
  my ($start,$end,$range);

  return () unless (defined $pool && ref($pool) eq 'HASH');

  if (defined $$pool{start} && defined $$pool{end}) {
    return ($$pool{start},$$pool{end});
  }

  if (defined $$pool{'start-address'} && defined $$pool{'end-address'}) {
    return ($$pool{'start-address'},$$pool{'end-address'});
  }

  $range = $$pool{pool};
  return () unless (defined $range);
  return ($1,$2) if ($range =~ /^\s*(\S+)\s*\-\s*(\S+)\s*$/);

  return ();
}

sub _append_kea_host($$$$$) {
  my ($data,$reservation,$v6,$hostcounter,$seenhosts) = @_;
  my ($name,$ip,$id_line,@host_data);

  return unless (defined $reservation && ref($reservation) eq 'HASH');

  $name = $$reservation{hostname};
  unless (defined $name && $name ne '') {
    $$hostcounter++;
    $name = "host-$$hostcounter";
  }

  if ($$seenhosts{$name}) {
    $$hostcounter++;
    $name .= "-$$hostcounter";
  }
  $$seenhosts{$name}=1;

  if (!$v6) {
    $ip = $$reservation{'ip-address'};
    $id_line = $$reservation{'hw-address'};
    return unless (defined $ip && $ip ne '' && defined $id_line && $id_line ne '');

    push @host_data, "fixed-address $ip;";
    push @host_data, "hardware ethernet $id_line;";
  }
  else {
    $ip = $$reservation{'ip-address'};
    if ((!defined $ip || $ip eq '') && ref($$reservation{'ip-addresses'}) eq 'ARRAY') {
      $ip = $$reservation{'ip-addresses'}->[0];
    }

    $id_line = $$reservation{duid};
    return unless (defined $ip && $ip ne '' && defined $id_line && $id_line ne '');

    $id_line = _normalize_hex_sequence($id_line);
    push @host_data, "fixed-address6 $ip;";
    push @host_data, "host-identifier option dhcp6.client-id $id_line;";
  }

  _append_option_data_lines(\@host_data,$$reservation{'option-data'});
  $$data{host}->{$name} = \@host_data;
}

sub _append_kea_subnet($$$$$$$) {
  my ($data,$subnet,$v6,$shared_name,$poolcounter,$hostcounter,$seenhosts) = @_;
  my ($subnet_key,$pool_key,$key,@subnet_data,$vlan_name);

  return unless (defined $subnet && ref($subnet) eq 'HASH');
  return unless (defined $$subnet{subnet} && $$subnet{subnet} ne '');

  $subnet_key = (!$v6 ? 'subnet' : 'subnet6');
  $pool_key = (!$v6 ? 'pool' : 'pool6');

  if (!$v6) {
    $key = _kea_ipv4_subnet_key($$subnet{subnet});
    return unless ($key);
  }
  else {
    $key = $$subnet{subnet};
  }

  if (defined $shared_name && $shared_name ne '') {
    $vlan_name = ($shared_name =~ /\s/ ? "\"$shared_name\"" : $shared_name);
    push @subnet_data, "VLAN $vlan_name";
  }

  _append_option_data_lines(\@subnet_data,$$subnet{'option-data'});
  $$data{$subnet_key}->{$key} = \@subnet_data;

  foreach my $pool (@{_arrayref($$subnet{pools})}) {
    my ($start,$end) = _kea_pool_bounds($pool);
    my @pool_data;
    my $pool_name;

    next unless ($start && $end);

    $$poolcounter++;
    $pool_name = (!$v6 ? "pool-$$poolcounter" : "pool6-$$poolcounter");

    push @pool_data, (!$v6 ? "range $start $end;" : "range6 $start $end;");
    _append_option_data_lines(\@pool_data,$$pool{'option-data'});

    $$data{$pool_key}->{$pool_name} = \@pool_data;
  }

  foreach my $res (@{_arrayref($$subnet{reservations})}) {
    _append_kea_host($data,$res,$v6,$hostcounter,$seenhosts);
  }
}

sub _append_kea_class($$) {
  my ($data,$class) = @_;
  my ($name,$test,@class_data);

  return unless (defined $class && ref($class) eq 'HASH');

  $name = $$class{name};
  return if (ref($name));
  return unless (defined $name && $name ne '');

  $test = $$class{test};
  if (defined $test && !ref($test)) {
    $test =~ s/(^\s+|\s+$)//g;
    push @class_data, "match if $test;" if ($test ne '');
  }
  _append_option_data_lines(\@class_data,$$class{'option-data'});

  $$data{class}->{$name} = \@class_data;
}

sub _netmask_to_bits($) {
  my ($mask) = @_;
  my ($bits,$bin);

  return undef unless (defined $mask);
  return undef unless ($mask =~ /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$/);

  $mask = $1;
  return undef if ($mask =~ /(^\.|\.$|\.\.|[^\d\.])/);

  $bits = 0;
  $bin = '';
  foreach my $octet (split(/\./,$mask)) {
    return undef if ($octet < 0 || $octet > 255);
    $bin .= sprintf('%08b',$octet);
  }

  return undef unless ($bin =~ /^1*0*$/);
  ($bits) = ($bin =~ /^(1*)/);
  return length($bits);
}

sub _subnet_key_to_kea_cidr($$) {
  my ($key,$v6) = @_;
  my ($ip,$mask,$bits);

  return undef unless (defined $key && $key ne '');

  if ($v6) {
    return $key if (cidr6ok($key));
    return undef;
  }

  return undef
    unless ($key =~ /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+netmask\s+(\d{1,3}(?:\.\d{1,3}){3})\s*$/i);

  ($ip,$mask) = ($1,$2);
  $bits = _netmask_to_bits($mask);
  return undef unless (defined $bits);

  return "$ip/$bits";
}

sub _cidr_prefixlen($) {
  my ($cidr) = @_;

  return 0 unless (defined $cidr);
  return $1 if ($cidr =~ /\/(\d{1,3})\s*$/);
  return 0;
}

sub _line_to_kea_option_data($) {
  my ($line) = @_;
  my ($name,$data,$space,%opt);

  return undef unless (defined $line);
  return undef unless ($line =~ /^\s*option\s+([A-Za-z0-9_\.-]+)\s*(.*?)\s*;\s*$/);

  ($name,$data) = ($1,$2);
  $space = '';

  if ($name =~ /^([^.]+)\.(.+)$/) {
    ($space,$name) = ($1,$2);
  }

  %opt = (name => $name);
  $opt{space} = $space if ($space ne '');
  $opt{data} = $data if (defined $data && $data ne '');

  return \%opt;
}

sub _pool_range_from_lines($$) {
  my ($lines,$v6) = @_;
  my ($start,$end);

  return () unless (defined $lines && ref($lines) eq 'ARRAY');

  foreach my $line (@$lines) {
    next unless (defined $line);

    if (!$v6 && $line =~ /^\s*range\s+(\S+)(?:\s+(\S+))?\s*;\s*$/) {
      ($start,$end) = ($1,($2 ? $2 : $1));
      last;
    }

    if ($v6 && $line =~ /^\s*range6\s+(\S+)(?:\s+(\S+))?\s*;\s*$/) {
      ($start,$end) = ($1,($2 ? $2 : $1));
      last;
    }
  }

  return () unless ($start && $end);
  return ($start,$end);
}

sub _ip_in_cidr($$) {
  my ($ip,$cidr) = @_;
  my ($net,$addr,$overlap);

  return 0 unless ($ip && $cidr);

  $net = new Net::IP($cidr);
  $addr = new Net::IP($ip);
  return 0 unless ($net && $addr);

  $overlap = $net->overlaps($addr);
  return ($overlap == $IP_B_IN_A_OVERLAP || $overlap == $IP_IDENTICAL) ? 1 : 0;
}

sub _pool_in_cidr($$$) {
  my ($start,$end,$cidr) = @_;

  return 0 unless ($start && $end && $cidr);
  return (_ip_in_cidr($start,$cidr) && _ip_in_cidr($end,$cidr)) ? 1 : 0;
}

sub _strip_isc_directive_value($) {
  my ($val) = @_;

  return '' unless (defined $val);
  $val =~ s/^\s+|\s+$//g;
  $val =~ s/^"(.*)"$/$1/;
  return $val;
}

sub _dedupe_option_data($) {
  my ($opts) = @_;
  my (%seen,@out,$i,$opt,$key,$space,$name);

  return [] unless (defined $opts && ref($opts) eq 'ARRAY');

  for ($i=$#$opts;$i>=0;$i--) {
    $opt = $$opts[$i];
    next unless (defined $opt && ref($opt) eq 'HASH' && defined $$opt{name});

    $space = (defined $$opt{space} && $$opt{space} ne '' ? $$opt{space} . '.' : '');
    $name = $$opt{name};
    $key = lc($space . $name);

    next if ($seen{$key}++);
    unshift @out,$opt;
  }

  return \@out;
}

sub _append_user_context_lines($$) {
  my ($obj,$lines) = @_;
  my ($ctx,$lst);

  return unless (defined $obj && ref($obj) eq 'HASH');
  return unless (defined $lines && ref($lines) eq 'ARRAY' && @$lines > 0);

  $ctx = $$obj{'user-context'};
  unless (defined $ctx && ref($ctx) eq 'HASH') {
    $ctx = {};
    $$obj{'user-context'} = $ctx;
  }

  $lst = $$ctx{'sauron-isc-extra'};
  unless (defined $lst && ref($lst) eq 'ARRAY') {
    $lst = [];
    $$ctx{'sauron-isc-extra'} = $lst;
  }

  push @$lst, @$lines;
}

sub _ensure_user_context_hash($) {
  my ($obj) = @_;
  my ($ctx);

  return {} unless (defined $obj && ref($obj) eq 'HASH');

  $ctx = $$obj{'user-context'};
  unless (defined $ctx && ref($ctx) eq 'HASH') {
    $ctx = {};
    $$obj{'user-context'} = $ctx;
  }

  return $ctx;
}

sub _apply_isc_directive_to_object($$$$) {
  my ($obj,$line,$v6,$scope) = @_;
  my ($tmp,$key,$value);

  return 0 unless (defined $obj && ref($obj) eq 'HASH' && defined $line && defined $scope);

  if (!$v6) {
    if ($scope eq 'global') {
      if ($line =~ /^\s*authoritative\s*;\s*$/i) {
        $$obj{authoritative} = JSON::PP::true;
        return 1;
      }
      if ($line =~ /^\s*not\s+authoritative\s*;\s*$/i) {
        $$obj{authoritative} = JSON::PP::false;
        return 1;
      }

      if ($line =~ /^\s*default-lease-time\s+(\d+)\s*;\s*$/i) {
        $$obj{'valid-lifetime'} = int($1);
        return 1;
      }
      if ($line =~ /^\s*min-lease-time\s+(\d+)\s*;\s*$/i) {
        $$obj{'min-valid-lifetime'} = int($1);
        return 1;
      }
      if ($line =~ /^\s*max-lease-time\s+(\d+)\s*;\s*$/i) {
        $$obj{'max-valid-lifetime'} = int($1);
        return 1;
      }

      if ($line =~ /^\s*ddns-update-style\s+none\s*;\s*$/i) {
        $$obj{'ddns-send-updates'} = JSON::PP::false;
        return 1;
      }
      if ($line =~ /^\s*ddns-update-style\s+\S+\s*;\s*$/i) {
        $$obj{'ddns-send-updates'} = JSON::PP::true;
        return 1;
      }
    }

    if ($scope =~ /^(global|subnet|host)$/) {
      if ($line =~ /^\s*next-server\s+(.+?)\s*;\s*$/i) {
        $tmp = _strip_isc_directive_value($1);
        $$obj{'next-server'} = $tmp if ($tmp ne '');
        return 1;
      }
      if ($line =~ /^\s*filename\s+(.+?)\s*;\s*$/i) {
        $tmp = _strip_isc_directive_value($1);
        $$obj{'boot-file-name'} = $tmp if ($tmp ne '');
        return 1;
      }
      if ($line =~ /^\s*server-name\s+(.+?)\s*;\s*$/i) {
        $tmp = _strip_isc_directive_value($1);
        $$obj{'server-hostname'} = $tmp if ($tmp ne '');
        return 1;
      }
    }
  }

  if ($scope =~ /^(global|subnet)$/) {
    if ($line =~ /^\s*(preferred-lifetime|valid-lifetime|renew-timer|rebind-timer|min-preferred-lifetime|max-preferred-lifetime|min-valid-lifetime|max-valid-lifetime)\s+(\d+)\s*;\s*$/i) {
      $key = lc($1);
      $value = int($2);
      $$obj{$key} = $value;
      return 1;
    }
  }

  return 0;
}

sub _extract_host_groups($) {
  my ($host_lines) = @_;
  my (@groups,%seen,$line,$group);

  return [] unless (defined $host_lines && ref($host_lines) eq 'ARRAY');

  foreach $line (@$host_lines) {
    next unless (defined $line);
    next unless ($line =~ /^\s*GROUP\s+(\S+)\s*$/);
    $group = $1;
    next if ($seen{$group}++);
    push @groups, $group;
  }

  return \@groups;
}

sub _host_lines_with_group_inheritance($$) {
  my ($data,$host_lines) = @_;
  my (@merged,$line,$group,$groups);

  return [] unless (defined $host_lines && ref($host_lines) eq 'ARRAY');

  $groups = _extract_host_groups($host_lines);
  foreach $group (@$groups) {
    next unless (defined $$data{group} && ref($$data{group}) eq 'HASH');
    next unless (defined $$data{group}->{$group} && ref($$data{group}->{$group}) eq 'ARRAY');
    push @merged, @{$$data{group}->{$group}};
  }

  foreach $line (@$host_lines) {
    next unless (defined $line);
    next if ($line =~ /^\s*GROUP\s+/);
    push @merged, $line;
  }

  return \@merged;
}

sub _reservation_hostname_with_suffix($$$$) {
  my ($hostname,$index,$count,$ip) = @_;
  my ($suffix);

  return $hostname if ($count < 2 && $index == 0);

  $suffix = (defined $ip ? $ip : ($index + 1));
  $suffix =~ s/[^0-9A-Za-z]+/-/g;
  $suffix =~ s/^-+|-+$//g;
  $suffix = ($suffix ne '' ? $suffix : ($index + 1));

  return $hostname . '-' . $suffix;
}

sub _split_isc_fixed_address_list($$) {
  my ($raw,$v6) = @_;
  my (@parts,@ips,$part,$ip);

  return [] unless (defined $raw);

  @parts = split(/\s*,\s*/,$raw);
  @parts = split(/\s+/,$raw) if (@parts < 2 && $raw =~ /\s+/);

  foreach $part (@parts) {
    next unless (defined $part);
    $part =~ s/^\s+|\s+$//g;
    next unless ($part ne '');

    if (!$v6 && is_ip($part) && $part !~ /:/) {
      push @ips, $part;
      next;
    }
    if ($v6 && is_ip($part) && $part =~ /:/) {
      push @ips, $part;
      next;
    }
  }

  return \@ips;
}

sub _host_to_kea_reservations($$$$) {
  my ($hostname,$lines,$v6,$base_obj) = @_;
  my ($id,@ips,@opts,@extra,$line,$opt,$tmpips,$res,
      @reservations,$deduped_opts,$i,%template);

  return [] unless (defined $hostname && defined $lines && ref($lines) eq 'ARRAY');

  %template = (%{$base_obj || {}});

  foreach $line (@$lines) {
    next unless (defined $line);

    if (!$v6 && $line =~ /^\s*fixed-address\s+(\S.*)\s*;\s*$/) {
      $tmpips = _split_isc_fixed_address_list($1,$v6);
      push @ips, @$tmpips if (defined $tmpips && ref($tmpips) eq 'ARRAY');
      next;
    }
    if ($v6 && $line =~ /^\s*fixed-address6\s+(\S.*)\s*;\s*$/) {
      $tmpips = _split_isc_fixed_address_list($1,$v6);
      push @ips, @$tmpips if (defined $tmpips && ref($tmpips) eq 'ARRAY');
      next;
    }

    if (!$v6 && $line =~ /^\s*hardware\s+ethernet\s+(\S+)\s*;\s*$/i) {
      $id = lc($1);
      next;
    }

    if ($v6 && $line =~ /^\s*host-identifier\s+option\s+dhcp6\.client-id\s+(\S+)\s*;\s*$/i) {
      $id = lc($1);
      $id =~ s/://g;
      next;
    }

    $opt = _line_to_kea_option_data($line);
    if ($opt) {
      push @opts,$opt;
      next;
    }

    if (_apply_isc_directive_to_object(\%template,$line,$v6,'host')) {
      next;
    }

    push @extra,$line;
  }

  return [] unless (@ips > 0 && $id);

  $deduped_opts = _dedupe_option_data(\@opts);

  for $i (0..$#ips) {
    my %item = (%template);

    $item{hostname} = _reservation_hostname_with_suffix($hostname,$i,scalar(@ips),$ips[$i]);

    if (!$v6) {
      $item{'hw-address'} = $id;
      $item{'ip-address'} = $ips[$i];
    }
    else {
      $item{duid} = $id;
      $item{'ip-addresses'} = [$ips[$i]];
    }

    $item{'option-data'} = [@$deduped_opts] if (@$deduped_opts > 0);
    _append_user_context_lines(\%item,\@extra);

    push @reservations, \%item;
  }

  return \@reservations;
}

sub _extract_vlan_marker($) {
  my ($line) = @_;
  my ($name);

  return undef unless (defined $line);
  return undef unless ($line =~ /^\s*VLAN\s+(\".*\"|\S+)\s*$/);

  $name = $1;
  $name =~ s/^\"//;
  $name =~ s/\"$//;

  return $name;
}

sub _make_kea_subnet_item($$$) {
  my ($key,$lines,$v6) = @_;
  my ($cidr,$vlan,@opts,%item,$opt,$tmp_vlan,@extra,$deduped_opts);

  return undef unless (defined $lines && ref($lines) eq 'ARRAY');

  $cidr = _subnet_key_to_kea_cidr($key,$v6);
  return undef unless ($cidr);

  foreach my $line (@$lines) {
    $tmp_vlan = _extract_vlan_marker($line);
    if (defined $tmp_vlan && $tmp_vlan ne '') {
      $vlan = $tmp_vlan;
      next;
    }

    $opt = _line_to_kea_option_data($line);
    if ($opt) {
      push @opts,$opt;
      next;
    }

    if (_apply_isc_directive_to_object(\%item,$line,$v6,'subnet')) {
      next;
    }

    push @extra,$line;
  }

  %item = (
    _cidr       => $cidr,
    _vlan       => $vlan,
    subnet      => $cidr,
    %item,
  );
  $deduped_opts = _dedupe_option_data(\@opts);
  $item{'option-data'} = $deduped_opts if (@$deduped_opts > 0);
  _append_user_context_lines(\%item,\@extra);

  return \%item;
}

sub build_kea_from_isc_data($$) {
  my ($data,$v6) = @_;
  my ($subnet_key,$pool_key,$kea_subnet_key,$global_ref,
      @global_opts,@global_extra,@subnets,@ordered_subnets,
      @classes,@shared_names,%shared_map,%shared_opts,%shared_extra,
      %section,$line,$opt,$class,$class_ref,$test,
      $pool_ref,$pool_name,$start,$end,@pool_opts,@pool_extra,$pool_obj,
      @subnet_matches,$subnet_obj,$host_ref,$host_name,$host_lines,
      $res_lst,$res_obj,$res_ip,@res_matches,$shared_name,$shared_obj,
      @shared_list,@top_subnets,%seen_shared,@class_opts,@class_extra,
      $ctx,$deduped_opts,@unmapped_reservations,
      $shared_opts_ref,$shared_extra_ref);

  _init_data_refs($data);

  $subnet_key = (!$v6 ? 'subnet' : 'subnet6');
  $pool_key = (!$v6 ? 'pool' : 'pool6');
  $kea_subnet_key = (!$v6 ? 'subnet4' : 'subnet6');

  # Global options and known ISC directives.
  $global_ref = _arrayref($$data{GLOBAL});
  foreach $line (@$global_ref) {
    $opt = _line_to_kea_option_data($line);
    if ($opt) {
      push @global_opts,$opt;
      next;
    }

    if (_apply_isc_directive_to_object(\%section,$line,$v6,'global')) {
      next;
    }

    push @global_extra,$line;
  }
  $deduped_opts = _dedupe_option_data(\@global_opts);
  $section{'option-data'} = $deduped_opts if (@$deduped_opts > 0);
  _append_user_context_lines(\%section,\@global_extra);

  # Shared-network level options.
  foreach $shared_name (sort keys %{$$data{'shared-network'}}) {
    my (@opts,@extra);
    foreach $line (@{_arrayref($$data{'shared-network'}->{$shared_name})}) {
      $opt = _line_to_kea_option_data($line);
      if ($opt) {
        push @opts,$opt;
        next;
      }

      # Keep unknown/non-option shared-network directives for compatibility.
      push @extra,$line;
    }

    $shared_opts{$shared_name} = _dedupe_option_data(\@opts) if (@opts > 0);
    $shared_extra{$shared_name} = [@extra] if (@extra > 0);
  }

  # Build subnet records.
  foreach my $key (sort keys %{$$data{$subnet_key}}) {
    my $item = _make_kea_subnet_item($key,$$data{$subnet_key}->{$key},$v6);
    push @subnets,$item if ($item);
  }

  # Prefer most-specific subnet when attaching pools and reservations.
  @ordered_subnets = sort {
    _cidr_prefixlen($$b{subnet}) <=> _cidr_prefixlen($$a{subnet})
  } @subnets;

  # Attach pools.
  foreach $pool_name (sort keys %{$$data{$pool_key}}) {
    $pool_ref = _arrayref($$data{$pool_key}->{$pool_name});
    ($start,$end) = _pool_range_from_lines($pool_ref,$v6);
    next unless ($start && $end);

    @pool_opts = ();
    @pool_extra = ();
    foreach $line (@$pool_ref) {
      next if ((!$v6 && $line =~ /^\s*range\s+/) || ($v6 && $line =~ /^\s*range6\s+/));

      $opt = _line_to_kea_option_data($line);
      if ($opt) {
        push @pool_opts,$opt;
        next;
      }

      push @pool_extra,$line;
    }

    $pool_obj = {
      pool => ($start eq $end ? $start : "$start - $end")
    };
    $deduped_opts = _dedupe_option_data(\@pool_opts);
    $$pool_obj{'option-data'} = $deduped_opts if (@$deduped_opts > 0);
    _append_user_context_lines($pool_obj,\@pool_extra);

    @subnet_matches = grep { _pool_in_cidr($start,$end,$$_{subnet}) } @ordered_subnets;
    next unless (@subnet_matches > 0);

    $subnet_obj = $subnet_matches[0];
    $$subnet_obj{pools} = [] unless (ref($$subnet_obj{pools}) eq 'ARRAY');
    push @{$$subnet_obj{pools}}, $pool_obj;
  }

  # Attach reservations with group inheritance and multi-IP split.
  foreach $host_name (sort keys %{$$data{host}}) {
    $host_ref = _arrayref($$data{host}->{$host_name});
    $host_lines = _host_lines_with_group_inheritance($data,$host_ref);
    $res_lst = _host_to_kea_reservations($host_name,$host_lines,$v6,{});

    foreach $res_obj (@$res_lst) {
      $res_ip = (!$v6 ? $$res_obj{'ip-address'} : $$res_obj{'ip-addresses'}->[0]);
      next unless ($res_ip);

      @res_matches = grep { _ip_in_cidr($res_ip,$$_{subnet}) } @ordered_subnets;
      unless (@res_matches > 0) {
        push @unmapped_reservations, $res_obj;
        next;
      }

      $subnet_obj = $res_matches[0];
      $$subnet_obj{reservations} = [] unless (ref($$subnet_obj{reservations}) eq 'ARRAY');
      push @{$$subnet_obj{reservations}}, $res_obj;
    }
  }

  # Client classes (best-effort conversion).
  foreach $class (sort keys %{$$data{class}}) {
    my %class_obj = (name => $class);
    @class_opts = ();
    @class_extra = ();
    $test = undef;
    $class_ref = _arrayref($$data{class}->{$class});

    foreach $line (@$class_ref) {
      if ($line =~ /^\s*match\s+if\s+(.+?)\s*;\s*$/i) {
        $test = $1;
        next;
      }

      $opt = _line_to_kea_option_data($line);
      if ($opt) {
        push @class_opts,$opt;
        next;
      }

      push @class_extra,$line;
    }

    $class_obj{test} = $test if (defined $test && $test ne '');
    $deduped_opts = _dedupe_option_data(\@class_opts);
    $class_obj{'option-data'} = $deduped_opts if (@$deduped_opts > 0);
    _append_user_context_lines(\%class_obj,\@class_extra);
    push @classes, \%class_obj;
  }
  $section{'client-classes'} = \@classes if (@classes > 0);

  # Group subnets by shared-network marker.
  foreach $subnet_obj (@subnets) {
    $shared_name = $$subnet_obj{_vlan};
    if (defined $shared_name && $shared_name ne '') {
      unless ($seen_shared{$shared_name}) {
        push @shared_names, $shared_name;
        $seen_shared{$shared_name} = 1;
      }
      $shared_map{$shared_name} = [] unless (ref($shared_map{$shared_name}) eq 'ARRAY');
      push @{$shared_map{$shared_name}}, $subnet_obj;
    }
    else {
      push @top_subnets, $subnet_obj;
    }
  }

  foreach $shared_name (@shared_names) {
    $shared_obj = {
      name => $shared_name,
      $kea_subnet_key => []
    };

    $shared_opts_ref = $shared_opts{$shared_name};
    $$shared_obj{'option-data'} = $shared_opts_ref
      if (ref($shared_opts_ref) eq 'ARRAY' && @$shared_opts_ref > 0);

    $shared_extra_ref = $shared_extra{$shared_name};
    _append_user_context_lines($shared_obj,$shared_extra_ref)
      if (ref($shared_extra_ref) eq 'ARRAY' && @$shared_extra_ref > 0);

    foreach $subnet_obj (@{$shared_map{$shared_name}}) {
      my %clean = %{$subnet_obj};
      delete $clean{_cidr};
      delete $clean{_vlan};
      push @{$$shared_obj{$kea_subnet_key}}, \%clean;
    }
    push @shared_list, $shared_obj;
  }
  $section{'shared-networks'} = \@shared_list if (@shared_list > 0);

  if (@top_subnets > 0) {
    my @clean_subnets;
    foreach $subnet_obj (@top_subnets) {
      my %clean = %{$subnet_obj};
      delete $clean{_cidr};
      delete $clean{_vlan};
      push @clean_subnets, \%clean;
    }
    $section{$kea_subnet_key} = \@clean_subnets;
  }

  if (@unmapped_reservations > 0) {
    $ctx = _ensure_user_context_hash(\%section);
    $$ctx{'sauron-unmapped-reservations'} = \@unmapped_reservations;
  }

  return \%section;
}


sub is_kea_dhcpconf($) {
  my ($filename) = @_;
  my $fh = IO::File->new();

  return 0 unless (-r $filename);
  open($fh,$filename) || return 0;

  while (<$fh>) {
    s/^\s+//;
    s/\s+$//;

    next if ($_ eq '');
    next if (/^#/ || m{^//} || m{^/\*} || /^\*/);

    close($fh);
    return (/^\{/) ? 1 : 0;
  }

  close($fh);
  return 0;
}

# parse dhcpd.conf file, build hash of all entries in the file
#
sub process_dhcpdconf($$$) {
  my ($filename,$data,$v6)=@_;

  my $fh = IO::File->new();
  my ($i,$c,$tmp,$quote,$lend,$fline,$prev,%state);

  print "process_dhcpdconf($filename,DATA)\n" if ($debug);

  fatal("cannot read conf file: $filename") unless (-r $filename);
  open($fh,$filename) || fatal("cannot open conf file: $filename");

  $tmp='';
  while (<$fh>) {
    chomp;
    next if (/^\s*$/);
    next if (/^\s*#/);

    $quote=0;
#    print "line '$_'\n";
    s/\s+/\ /g; s/\s+$//; # s/^\s+//;

    for $i (0..length($_)-1) {
      $prev=($i > 0 ? substr($_,$i-1,1) : ' ');
      $c=substr($_,$i,1);
      $quote=($quote ? 0 : 1)	if (($c eq '"') && ($prev ne '\\'));
      unless ($quote) {
	last if ($c eq '#');
	$lend = ($c =~ /^[;{}]$/ ? 1 : 0);
      }
      $tmp .= $c;
      if ($lend) {
	process_line($tmp,$data,\%state,$v6);
	$tmp='';
      }
    }

    fatal("$filename($.): unterminated quoted string!\n") if ($quote);
  }
  process_line($tmp,$data,\%state,$v6);

  close($fh);

  _init_data_refs($data);

  return 0;
}


sub process_kea_dhcpconf($$$) {
  my ($filename,$data,$v6)=@_;
  my $fh = IO::File->new();
  my ($json_text,$root,$scope,$cfg,$subnet_key,$poolcounter,$hostcounter,%seenhosts);

  fatal("cannot read conf file: $filename") unless (-r $filename);
  open($fh,$filename) || fatal("cannot open conf file: $filename");

  $json_text = '';
  while (<$fh>) {
    $json_text .= $_;
  }
  close($fh);

  eval {
    my $json = JSON::PP->new();
    $json->relaxed(1);
    $root = $json->decode($json_text);
  };
  fatal("cannot parse KEA conf file: $filename ($@)") if ($@);

  fatal("invalid KEA conf root in $filename")
    unless (defined $root && ref($root) eq 'HASH');

  $scope = (!$v6 ? 'Dhcp4' : 'Dhcp6');
  $cfg = $root->{$scope};
  fatal("KEA conf does not include $scope section")
    unless (defined $cfg && ref($cfg) eq 'HASH');

  _init_data_refs($data);

  _append_option_data_lines($$data{GLOBAL},$$cfg{'option-data'});

  $poolcounter = 0;
  $hostcounter = 0;
  $subnet_key = (!$v6 ? 'subnet4' : 'subnet6');

  foreach my $shared (@{_arrayref($$cfg{'shared-networks'})}) {
    my ($name,@sn_data);

    next unless (defined $shared && ref($shared) eq 'HASH');

    $name = $$shared{name};
    unless (defined $name && $name ne '') {
      $name = "shared-network-" . ((scalar keys %{$$data{'shared-network'}}) + 1);
    }

    _append_option_data_lines(\@sn_data,$$shared{'option-data'});
    $$data{'shared-network'}->{$name} = \@sn_data;

    foreach my $subnet (@{_arrayref($$shared{$subnet_key})}) {
      _append_kea_subnet($data,$subnet,$v6,$name,\$poolcounter,\$hostcounter,\%seenhosts);
    }
  }

  foreach my $subnet (@{_arrayref($$cfg{$subnet_key})}) {
    _append_kea_subnet($data,$subnet,$v6,undef,\$poolcounter,\$hostcounter,\%seenhosts);
  }

  foreach my $class (@{_arrayref($$cfg{'client-classes'})}) {
    _append_kea_class($data,$class);
  }

  return 0;
}

sub process_line($$$$) {
  my($line,$data,$state,$v6) = @_;

  my($tmp,$block,$rest,$ref);

  return if ($line =~ /^\s*$/);
  $line =~ s/(^\s+|\s+$)//g;
  #$line =~ s/\"//g;


  #if ($line =~ /^(\S+)\s+(\S.*)?{$/) {
  if ($line =~ /^(\S+)\s?(\s+\S.*)?{$/) {
    $block=lc($1);
    #print "BLOCK: $block\n";
    ($rest=$2) =~ s/^\s+|\s+$//g;
    $rest =~ s/\"//g;
    #print "REST: $rest\n";
    if ($block =~ /^(group)/) {
      # generate name for groups
      $$state{groupcounter}++;
      my $groupname = (!$v6 ? "group" : "group6");
      $rest="$groupname-" . $$state{groupcounter};
    }
    elsif ($block =~ /^(pool[6]?)/) {
      $$state{poolcounter}++;
      $rest="$1-" . $$state{poolcounter};

#warn("pools not under shared-network aren't currently supported");
    }
    #print "begin '$block:$rest'\n";
    unshift @{$$state{BLOCKS}}, $block;
    unshift @{$$state{$block}}, $rest;
    $$data{$block}->{$rest}=[] if ($rest);
    $$state{rest}=$2;

    if ($block =~ /^host/) {
      push @{$$data{$block}->{$rest}}, "GROUP $$state{group}->[0]" if ($$state{group}->[0]);
    }
    if ($block =~ /^subnet[6]?/) {
      if ($$state{'shared-network'}->[0]) {
         push @{$$data{$block}->{$rest}}, "VLAN $$state{'shared-network'}->[0]";
      }
      $$state{lastsubnet} = $rest;
    }

    return 0;
  }

  $block=$$state{BLOCKS}->[0];
  $rest=$$state{$block}->[0];

  if ($line =~ /^\s*}\s*$/) {
    #print "end '$block:$rest'\n";
    unless (@{$$state{BLOCKS}} > 0) {
      warn("mismatched parenthesis");
      return -1;
    }
    shift @{$$state{BLOCKS}};
    shift @{$$state{$block}};
    return 0;
  }

  $block='GLOBAL' unless ($block);
  #print "line($block:$rest) '$line'\n";

  if ($block eq 'GLOBAL') {
    #if($line =~ /subclass\s+\"(.*)\"\s+(.*)/) {
    if($line =~ /subclass\s+\"(.*)\"\s+(.*)/) {
        push @{$$data{'subclass'}->{$1}}, $2;
    }
    else {
        push @{$$data{GLOBAL}}, $line;
    }
  }
  elsif ($block =~ /^(subnet[6]?|shared-network|group|class)$/) {
    push @{$$data{$block}->{$rest}}, $line;
  }
  elsif ($block =~ /^pool[6]?/) {
    push @{$$data{$block}->{$rest}}, $line;
  }
  elsif ($block =~ /^host/) {
    push @{$$data{$block}->{$rest}}, $line;
  }


  return 0;
}

1;
# eof
