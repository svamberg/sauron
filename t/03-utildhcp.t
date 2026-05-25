#!/usr/bin/perl
# t/03-utildhcp.t - Unit tests for Sauron::UtilDhcp (DHCP conf parsing, no DB)
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/..";
use Test::More;
use File::Temp qw(tempfile);

# Ensure DB.pm symlink
my $db_link = "$FindBin::Bin/../Sauron/DB.pm";
unless (-e $db_link) {
    symlink("DB-DBI.pm", $db_link) or die "Cannot create DB.pm symlink: $!";
}

# Globals needed by transitive imports
our $SAURON_DNSNAME_CHECK_LEVEL = 0;
our %perms = (alevel => 0);

use Sauron::UtilDhcp;

my $testdata = "$FindBin::Bin/../test";

# =========================================================================
# process_dhcpdconf - v4
# =========================================================================
subtest 'process_dhcpdconf v4' => sub {
    my $conf_file = "$testdata/dhcpd.conf";
    plan skip_all => "test/dhcpd.conf not found" unless -r $conf_file;

    my %data;
    process_dhcpdconf($conf_file, \%data, 0);

    ok(scalar keys %data > 0, 'parsed data has entries');
    ok(ref $data{'shared-network'} eq 'HASH', 'shared-network structure parsed');
    ok(ref $data{subnet} eq 'HASH', 'subnet structure parsed');
    ok(scalar keys %{$data{'shared-network'}} > 0, 'shared-network entries found');
    ok(exists $data{subnet}{'10.10.100.0 netmask 255.255.255.0'}, 'known subnet key parsed');
};

# =========================================================================
# build_kea_from_isc_data - v4
# =========================================================================
subtest 'build_kea_from_isc_data v4' => sub {
    my $conf_file = "$testdata/dhcpd.conf";
    plan skip_all => "test/dhcpd.conf not found" unless -r $conf_file;

    my %data;
    process_dhcpdconf($conf_file, \%data, 0);
    my $kea = build_kea_from_isc_data(\%data, 0);

    ok(ref $kea eq 'HASH', 'KEA conversion returns hashref');
    ok(ref $kea->{'shared-networks'} eq 'ARRAY', 'shared-networks exported');

    my ($servers1) = grep { $_->{name} eq 'servers1' } @{$kea->{'shared-networks'} || []};
    ok($servers1, 'servers1 shared-network found');
    ok(ref $servers1->{subnet4} eq 'ARRAY' && @{$servers1->{subnet4}} > 0,
       'subnet4 entries present for shared-network');

    my ($subnet) = grep { $_->{subnet} eq '10.10.100.0/24' } @{$servers1->{subnet4} || []};
    ok($subnet, 'subnet converted from netmask syntax to CIDR');

    ok(ref $subnet->{reservations} eq 'ARRAY' && @{$subnet->{reservations}} > 0,
       'reservations exported under subnet');
    my ($ws1) = grep { $_->{hostname} eq 'ws1.middle.earth' } @{$subnet->{reservations} || []};
    ok($ws1, 'known reservation mapped into subnet');
    is($ws1->{'ip-address'}, '10.10.100.100', 'reservation IP preserved');
    is($ws1->{'hw-address'}, '00:30:40:50:60:00', 'reservation hw-address preserved');

        ok($kea->{authoritative}, 'global authoritative mapped');
        is($kea->{'valid-lifetime'}, 32000, 'default-lease-time mapped to valid-lifetime');
        is($kea->{'max-valid-lifetime'}, 64000, 'max-lease-time mapped to max-valid-lifetime');
        ok(defined $kea->{'ddns-send-updates'} && !$kea->{'ddns-send-updates'},
             'ddns-update-style none mapped to ddns-send-updates=false');

        ok(ref $kea->{'user-context'} eq 'HASH', 'user-context exists for unmapped directives');
        my $global_extra = join("\n", @{$kea->{'user-context'}{'sauron-isc-extra'} || []});
        like($global_extra, qr/^allow bootp;/m, 'unmapped global directive preserved');

        my ($chaos) = grep { $_->{name} eq 'CHAOS' } @{$kea->{'shared-networks'} || []};
        ok($chaos, 'CHAOS shared-network found');
        my ($subnet30) = grep { $_->{subnet} eq '10.10.30.0/24' } @{$chaos->{subnet4} || []};
        ok($subnet30, 'terminal subnet found');

        my ($terminal1) = grep { $_->{hostname} eq 'terminal1.middle.earth' } @{$subnet30->{reservations} || []};
        ok($terminal1, 'group host reservation exported');
        is($terminal1->{'next-server'}, 'nfs.middle.earth', 'group next-server inherited into reservation');

        my $t1_opts = join("\n", map { $_->{name} . ' ' . ($_->{data} || '') } @{$terminal1->{'option-data'} || []});
        like($t1_opts, qr/root-path\s+"\/export\/linux-terminal"/, 'group option root-path inherited into reservation');
};

# =========================================================================
# build_kea_from_isc_data - multi IP host split
# =========================================================================
subtest 'build_kea_from_isc_data multi-ip split' => sub {
        my ($fh, $tmpfile) = tempfile();
        print {$fh} <<'CONF';
shared-network "lab" {
    subnet 192.0.2.0 netmask 255.255.255.0 {
        option routers 192.0.2.1;
    }
}

host multi.example {
    fixed-address 192.0.2.10, 192.0.2.11;
    hardware ethernet 00:11:22:33:44:55;
}
CONF
        close $fh;

        my %data;
        process_dhcpdconf($tmpfile, \%data, 0);
        my $kea = build_kea_from_isc_data(\%data, 0);

        my ($lab) = grep { $_->{name} eq 'lab' } @{$kea->{'shared-networks'} || []};
        ok($lab, 'shared-network from fixture found');
        my ($subnet) = grep { $_->{subnet} eq '192.0.2.0/24' } @{$lab->{subnet4} || []};
        ok($subnet, 'fixture subnet found');

        my @multi = grep {
                defined $_->{'hw-address'} && $_->{'hw-address'} eq '00:11:22:33:44:55'
        } @{$subnet->{reservations} || []};
        is(scalar(@multi), 2, 'multi fixed-address host is split into two reservations');

        my %ips = map { $_->{'ip-address'} => 1 } @multi;
        ok($ips{'192.0.2.10'} && $ips{'192.0.2.11'}, 'both fixed-address values are preserved');

        my %hn = map { $_->{hostname} => 1 } @multi;
        is(scalar(keys %hn), 2, 'split reservations use unique hostnames');
};

# =========================================================================
# KEA format detection
# =========================================================================
subtest 'is_kea_dhcpconf detection' => sub {
    my $isc_conf = "$testdata/dhcpd.conf";
    my $kea_conf = "$testdata/kea-dhcp.json";
    plan skip_all => "KEA/ISC fixtures not found" unless -r $isc_conf && -r $kea_conf;

    ok(!is_kea_dhcpconf($isc_conf), 'ISC dhcpd.conf is not detected as KEA');
    ok(is_kea_dhcpconf($kea_conf), 'KEA JSON is detected');
};

# =========================================================================
# process_kea_dhcpconf - v4
# =========================================================================
subtest 'process_kea_dhcpconf v4' => sub {
    my $conf_file = "$testdata/kea-dhcp.json";
    plan skip_all => "test/kea-dhcp.json not found" unless -r $conf_file;

    my %data;
    process_kea_dhcpconf($conf_file, \%data, 0);

    ok(exists $data{'shared-network'}{'kea-lab'}, 'shared-network imported from KEA');
    ok(exists $data{subnet}{'10.250.1.0 netmask 255.255.255.0'}, 'KEA subnet converted to netmask format');
    ok(exists $data{pool}{'pool-1'}, 'KEA pool imported');
    ok(exists $data{host}{'kea-ws1.middle.earth'}, 'KEA reservation imported as host');

    like(join("\n", @{$data{GLOBAL}}),
        qr/option domain-name-servers ns1\.middle\.earth,ns2\.middle\.earth;/,
        'KEA global option converted');
    like(join("\n", @{$data{subnet}{'10.250.1.0 netmask 255.255.255.0'}}),
        qr/^VLAN kea-lab/m,
        'subnet bound to shared-network via VLAN marker');
    like($data{pool}{'pool-1'}->[0],
        qr/^range 10\.250\.1\.100 10\.250\.1\.110;/,
        'pool range converted to ISC-like syntax');
    like(join("\n", @{$data{host}{'kea-ws1.middle.earth'}}),
        qr/hardware ethernet 00:30:40:50:60:70;/,
        'host hardware address retained');
};

# =========================================================================
# process_kea_dhcpconf - v6
# =========================================================================
subtest 'process_kea_dhcpconf v6' => sub {
    my $conf_file = "$testdata/kea-dhcp.json";
    plan skip_all => "test/kea-dhcp.json not found" unless -r $conf_file;

    my %data;
    process_kea_dhcpconf($conf_file, \%data, 1);

    ok(exists $data{subnet6}{'2001:db8:250::/64'}, 'KEA DHCPv6 subnet imported');
    ok(exists $data{pool6}{'pool6-1'}, 'KEA DHCPv6 pool imported');
    ok(exists $data{host}{'kea-host6.middle.earth'}, 'KEA DHCPv6 reservation imported as host');

    like($data{pool6}{'pool6-1'}->[0],
        qr/^range6 2001:db8:250::100 2001:db8:250::1ff;/,
        'DHCPv6 pool converted to range6 syntax');
    like(join("\n", @{$data{host}{'kea-host6.middle.earth'}}),
        qr/fixed-address6 2001:db8:250::10;/,
        'DHCPv6 fixed address retained');
    like(join("\n", @{$data{host}{'kea-host6.middle.earth'}}),
        qr/host-identifier option dhcp6\.client-id 00:03:00:01:00:11:22:33:44:55;/,
        'DUID normalized for import-dhcp parser');
};

# =========================================================================
# process_kea_dhcpconf - class null-safety
# =========================================================================
subtest 'process_kea_dhcpconf class non-string test ignored' => sub {
        my ($fh, $tmpfile) = tempfile();
        print {$fh} <<'JSON';
{
    "Dhcp4": {
        "client-classes": [
            {
                "name": "non-string-test",
                "test": {"invalid": true}
            }
        ]
    }
}
JSON
        close $fh;

        my %data;
        process_kea_dhcpconf($tmpfile, \%data, 0);

        ok(exists $data{class}{'non-string-test'}, 'class record is imported');
        is_deeply($data{class}{'non-string-test'}, [], 'non-string class test does not produce match-if line');
};

done_testing();
