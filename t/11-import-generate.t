#!/usr/bin/perl
# t/11-import-generate.t - End-to-end integration: import zone → generate config
#
# Requires running PostgreSQL with initialized Sauron DB and installed Sauron.
# Skipped unless SAURON_TEST_DSN and SAURON_INSTALL_DIR are set.
#
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/..";
use Test::More;
use File::Temp qw(tempdir);
use JSON::PP;

my $install_dir = $ENV{SAURON_INSTALL_DIR} || '';
my $dsn         = $ENV{SAURON_TEST_DSN}    || '';

unless ($dsn && $install_dir && -d $install_dir) {
    plan skip_all => 'Set SAURON_TEST_DSN and SAURON_INSTALL_DIR for E2E tests';
}

my $testdata = "$FindBin::Bin/../test";

# =========================================================================
# import-zone
# =========================================================================
subtest 'import-zone middle.earth' => sub {
    my $cmd = "$install_dir/import-zone example middle.earth $testdata/middle.earth.zone 2>&1";
    my $out = `$cmd`;
    is($? >> 8, 0, "import-zone exits 0") or diag($out);
};

# =========================================================================
# generatehosts
# =========================================================================
subtest 'generatehosts' => sub {
    my $cmd = "$install_dir/generatehosts example middle.earth 'test0:N:' '2001:db8::1:1' 5 --commit --info ':DEP::' 2>&1";
    my $out = `$cmd`;
    is($? >> 8, 0, "generatehosts exits 0") or diag($out);
};

# =========================================================================
# import-dhcp
# =========================================================================
subtest 'import-dhcp' => sub {
    my $cmd = "$install_dir/import-dhcp --global example $testdata/dhcpd.conf 2>&1";
    my $out = `$cmd`;
    is($? >> 8, 0, "import-dhcp exits 0") or diag($out);
};

subtest 'import-dhcp KEA' => sub {
    my $conf = "$testdata/kea-dhcp.json";
    plan skip_all => 'test/kea-dhcp.json not found' unless -r $conf;

    my $cmd = "$install_dir/import-dhcp --kea --global example $conf 2>&1";
    my $out = `$cmd`;
    is($? >> 8, 0, "import-dhcp --kea exits 0") or diag($out);
};

# =========================================================================
# generate configs (bind, dhcp, dhcp6)
# =========================================================================
subtest 'sauron generate' => sub {
    my $gendir = tempdir(CLEANUP => 1);

    my $kea_cmd = "$install_dir/sauron --verbose --kea example $gendir 2>&1";
    my $kea_out = `$kea_cmd`;
    is($? >> 8, 0, "sauron --kea exits 0") or diag($kea_out);

    my $kea_file = "$gendir/kea-dhcp.json";
    ok(-r $kea_file, 'generated KEA JSON output exists');
    if (-r $kea_file) {
        my $json_text = '';
        if (open(my $fh, '<', $kea_file)) {
            local $/;
            $json_text = <$fh>;
            close($fh);
        } else {
            fail('KEA JSON output is readable');
            diag("cannot read $kea_file: $!");
        }

        my $parsed;
        my $ok = eval {
            $parsed = JSON::PP->new()->decode($json_text);
            1;
        };
        ok($ok, 'KEA JSON is valid') or diag($@);
        if ($ok) {
            ok(ref $parsed eq 'HASH', 'KEA root is JSON object');
            ok(exists $parsed->{Dhcp4}, 'KEA output includes Dhcp4 section');
            ok(exists $parsed->{Dhcp6}, 'KEA output includes Dhcp6 section');

            if (exists $parsed->{Dhcp4} && ref $parsed->{Dhcp4} eq 'HASH') {
                ok($parsed->{Dhcp4}{authoritative}, 'DHCP4 authoritative is exported');
                ok(defined $parsed->{Dhcp4}{'valid-lifetime'}, 'DHCP4 valid-lifetime is exported');

                my $terminal1;
                for my $sn (@{$parsed->{Dhcp4}{'shared-networks'} || []}) {
                    for my $sub (@{$sn->{subnet4} || []}) {
                        for my $res (@{$sub->{reservations} || []}) {
                            if (($res->{hostname} || '') eq 'terminal1.middle.earth') {
                                $terminal1 = $res;
                                last;
                            }
                        }
                        last if $terminal1;
                    }
                    last if $terminal1;
                }

                ok($terminal1, 'group-based reservation terminal1 is exported');
                if ($terminal1) {
                    is($terminal1->{'next-server'}, 'nfs.middle.earth',
                       'group next-server inherited in KEA reservation');
                    my $opts = join("\n", map { ($_->{name} || '') . ' ' . ($_->{data} || '') }
                                         @{$terminal1->{'option-data'} || []});
                    like($opts, qr/root-path\s+"\/export\/linux-terminal"/,
                         'group root-path option inherited in KEA reservation');
                }
            }
        }
    }

    ok(!-e "$gendir/dhcpd.conf", '--kea standalone does not keep dhcpd.conf');
    ok(!-e "$gendir/dhcpd6.conf", '--kea standalone does not keep dhcpd6.conf');

    for my $mode (qw(--bind --dhcp --dhcp6)) {
        my $cmd = "$install_dir/sauron --verbose $mode example $gendir 2>&1";
        my $out = `$cmd`;
        is($? >> 8, 0, "sauron $mode exits 0") or diag($out);
    }

    # Check that some output files exist
    my @files = glob("$gendir/*");
    ok(@files > 0, "generated files in output dir");
};

done_testing();
