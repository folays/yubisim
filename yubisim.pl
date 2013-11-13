#!/usr/bin/perl -w
#
# http://wiki.yubico.com/wiki/index.php/Yubikey : Yubikey token fields
# http://forum.yubico.com/viewtopic.php?f=16&t=69 : CRC ISO-13239
# http://forum.yubico.com/viewtopic.php?f=8&t=45 : Test vectors (-test)
# http://www.zyz.dk/yk/yubisim/yubi_simulator.php : Yubikey simulator
# https://upload.yubico.com/ : Yubico AES Key Upload
# http://demo.yubico.com/?tab=one-factor : Testing your Yubikey
#
# apt-get install libdigest-crc-perl libcrypt-rijndael-perl

use strict;
use warnings FATAL => qw(uninitialized);

use Getopt::Long qw(:config no_auto_abbrev require_order);
use Time::HiRes qw(gettimeofday);
use Digest::CRC qw(crc crc16);
use Crypt::Rijndael;
use JSON;
use Fcntl qw(:flock);
use Data::Dumper;
use Data::Hexdumper;

my %long_opts = ();
if (open FILE, "<", "$ENV{HOME}/.yubisim.conf")
{
    my $data = do { local $/ = undef; <FILE> };
    my $json = decode_json($data) or die;
    @long_opts{keys %$json} = values %$json;
    close FILE;
}
GetOptions("test" => \$long_opts{test},
	   "debug" => \$long_opts{debug},
	   "pub=s" => \$long_opts{public_id},
	   "sec=s" => \$long_opts{secret_id},
	   "key=s" => \$long_opts{aes_key},
    ) or die "bad options";

if ($long_opts{test})
{
    # Those public test vectors come from the URLs in the header.
    my %test_vectors = (
	public_id => "dteffuje",
	secret_id => "8792ebfe26cc",
	aes_key => "ecde18dbe76fbd0c33330f1c354871db",
    );
    @long_opts{keys %test_vectors} = values %test_vectors;
}
else
{
    die "public_id must be 12 modhex characters long" unless $long_opts{public_id} =~ m/^[cbdefghijklnrtuv]{1,12}$/o;
    $long_opts{public_id} = ("t" x (12 - length($long_opts{public_id}))).$long_opts{public_id};
    die "secret_id must be 12 hex characters long" unless $long_opts{secret_id} =~ m/^[0-9a-z]{12,12}$/o;
    die "aes_key must be 32 characters long" unless $long_opts{aes_key} =~ m/^[0-9a-z]{32,32}$/o;
}

my %values;

$values{secret_id} = pack("H*", $long_opts{secret_id});

if ($long_opts{test})
{
    $values{sess_counter} = pack("v", 19);
    $values{timecode} = substr(pack("V", 49712), 0, 3);
    $values{token_counter} = pack("C", 17);
    $values{random} = pack("v", 40904);
}
else
{
    my ($seconds, $microseconds) = gettimeofday;

    printf "TIME : %d.%06d\n", $seconds, $microseconds if $long_opts{debug};

    my $counter = &get_yubikey_global_counter_inc($long_opts{public_id});
    $values{sess_counter} = substr pack("V", $counter), 1, 2;
    $values{token_counter} = substr pack("V", $counter), 0, 1;

    $seconds %= 2**24 / 8;
    $values{timecode} = substr pack("V", $seconds * 8 + int(8 * $microseconds / 10**6)), 0, 3;

    $values{random} = pack("v", int(rand(2 ** 16)));
}

sub get_yubikey_global_counter_inc($)
{
    my ($public_id) = @_;

    open LOCK, ">", "$ENV{HOME}/.yubisim.counters.lock" or die;
    flock(LOCK, LOCK_EX) or die;
    my $json;
    if (open FILE, "<", "$ENV{HOME}/.yubisim.counters")
    {
	my $data = do { local $/ = undef; <FILE> };
	$json = decode_json($data) or die;
	close FILE or die;
    }
    my $yubi = $json->{$public_id} ||= {global_counter => 255};
    my $counter = $json->{$public_id}->{global_counter}++;
    open FILE, ">", "$ENV{HOME}/.yubisim.counters.tmp" or die;
    print FILE encode_json($json);
    close FILE or die;
    rename "$ENV{HOME}/.yubisim.counters.tmp", "$ENV{HOME}/.yubisim.counters" or die;
    close LOCK or die;
    return $counter;
}

my $data = join("", @values{qw(secret_id sess_counter timecode token_counter random)});

if ($long_opts{debug})
{
    foreach my $key (qw(secret_id sess_counter timecode token_counter random))
    {
	chomp (my $hex = hexdump($values{$key}, {output_format => join(" ", ("%C") x length($values{$key}))}));
	printf "%-16s [%d] -> %s\n", $key, length($values{$key}), $hex;
    }
    {
	chomp (my $hex = hexdump($data, {output_format => join(" ", ("%C") x length($data))}));
	printf "DATA [%d] : %s\n", length($data), $hex;
    }
}

my $checksum = Digest::CRC->new(width => 16, init => 0xffff, xorout => 0x0000, poly => 0x1021, refout => 1, refin => 1, cont => 1)->add($data)->digest;
printf "CHECKSUM: 0x%s\n", sprintf("%04x", $checksum) if $long_opts{debug};
$checksum = (~$checksum) & 0xffff;
printf "CHECKSUM: 0x%s\n", sprintf("%04x", $checksum) if $long_opts{debug};
my $bin_checksum = pack("S", $checksum);
printf "CHECKSUM TXT: %s\n", unpack("H*", $bin_checksum) if $long_opts{debug};

my $otp = $data.$bin_checksum;
printf "OTP: %s\n", unpack("H*", $otp) if $long_opts{debug};

my $crypt = Crypt::Rijndael->new(pack("H*", $long_opts{aes_key}), Crypt::Rijndael::MODE_ECB());
my $otp_crypted = $crypt->encrypt($otp);
printf "OTP CRYPTED: %s\n", unpack("H*", $otp_crypted) if $long_opts{debug};

my $token = unpack("H*", $otp_crypted);
$token =~ tr/0123456789abcdef/cbdefghijklnrtuv/;
$token = $long_opts{public_id}.$token;
printf "%s\n", $token;
