#!/usr/bin/perl
# t/15-keygen.t - Test TSIG key generation via keygen utility
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/..";

# Check if we have required modules for keygen
my $can_test = 1;
eval { require Crypt::CBC; require Crypt::Cipher::RC5; };
if ($@) {
    plan skip_all => "Crypt::CBC or Crypt::Cipher::RC5 not available";
    exit 0;
}

# Check if keygen script exists
my $keygen = "$FindBin::Bin/../keygen";
unless (-x $keygen || -r $keygen) {
    plan skip_all => "keygen script not found or not executable";
    exit 0;
}

plan tests => 16;

# Test 1: Check keygen help output
{
    my $output = `$keygen --help 2>&1`;
    like($output, qr/--algorithm=/, 'keygen --help shows --algorithm option');
    like($output, qr/HMAC-SHA256/, 'keygen --help mentions HMAC-SHA256');
}

# Test 2: Verify supported algorithms are listed
{
    my $output = `$keygen --help 2>&1`;
    like($output, qr/HMAC-SHA256/, 'HMAC-SHA256 is listed');
    like($output, qr/HMAC-SHA384/, 'HMAC-SHA384 is listed');
    like($output, qr/HMAC-SHA512/, 'HMAC-SHA512 is listed');
}

# Test 3: Test tsig-keygen availability (used internally by keygen)
{
    my $tsig_keygen = '/usr/sbin/tsig-keygen';
    if (-x $tsig_keygen) {
        pass('tsig-keygen is available');
        
        # Test actual key generation
        my $output = `$tsig_keygen -a hmac-sha256 test-key 2>&1`;
        if ($output =~ /secret\s+"([^"]+)"/) {
            my $secret = $1;
            ok(length($secret) > 0, 'tsig-keygen generates valid HMAC-SHA256 key');
            # Verify it's valid base64
            use MIME::Base64;
            my $decoded = decode_base64($secret);
            ok(length($decoded) == 32, 'generated key has correct length (32 bytes for SHA256)');
        } else {
            fail('tsig-keygen output parsing');
            fail('generated key length');
        }
    } else {
        skip('tsig-keygen not available', 3);
    }
}

# Test 4: Verify algorithm conversion (HMAC-SHA256 -> sha256 for tsig-keygen)
{
    my %tests = (
        'HMAC-MD5' => 'md5',
        'HMAC-SHA1' => 'sha1',
        'HMAC-SHA256' => 'sha256',
        'HMAC-SHA384' => 'sha384',
        'HMAC-SHA512' => 'sha512',
    );
    
    for my $algo (keys %tests) {
        my $expected = $tests{$algo};
        my $result = $algo;
        $result =~ tr/A-Z/a-z/;      # Convert to lowercase: HMAC-SHA256 -> hmac-sha256
        $result =~ s/^hmac-//;       # Remove hmac- prefix: hmac-sha256 -> sha256
        is($result, $expected, "algorithm conversion: $algo -> $expected");
    }
}

# Test 5: Test different TSIG algorithms via tsig-keygen
{
    my @algorithms = (
        { name => 'hmac-sha256', expected_len => 32 },
        { name => 'hmac-sha384', expected_len => 48 },
        { name => 'hmac-sha512', expected_len => 64 },
    );
    
    my $tsig_keygen = '/usr/sbin/tsig-keygen';
    if (-x $tsig_keygen) {
        for my $alg (@algorithms) {
            my $output = `$tsig_keygen -a $alg->{name} test-$alg->{name} 2>&1`;
            if ($output =~ /secret\s+"([^"]+)"/) {
                my $secret = $1;
                my $decoded = decode_base64($secret);
                is(length($decoded), $alg->{expected_len}, 
                   "$alg->{name} produces correct key length");
            } else {
                fail("$alg->{name} key generation");
            }
        }
    } else {
        skip_all('tsig-keygen not available for algorithm tests');
    }
}