package Wyrmgarde::Crypt;

use strict;
use warnings;
use utf8;
use Encode;
use Bytes::Random::Secure::Tiny;
use Crypt::Mode::CBC;
use Crypt::Eksblowfish::Bcrypt qw(en_base64 de_base64);

sub encrypt {
	my ($password_rawtxt, $key) = @_;
	my $password_enutf8 = encode('UTF-8', $password_rawtxt);
	my $password_base64 = en_base64($password_enutf8);
	my $rng = Bytes::Random::Secure::Tiny->new;
	my $iv = $rng->bytes(16);
	my $cipher = Crypt::Mode::CBC->new('AES');
	my $password_cipher = $cipher->encrypt($password_base64, $key, $iv);
	my $password_concat = $iv . $password_cipher;
	my $password_stored = en_base64($password_concat);
	return $password_stored;
}

sub decrypt {
	my ($password_stored, $key) = @_;
	my $password_concat = de_base64($password_stored);
	my $iv = substr($password_concat, 0, 16);
	my $password_cipher = substr($password_concat, 16);
	my $cipher = Crypt::Mode::CBC->new('AES');
	my $password_base64 = $cipher->decrypt($password_cipher, $key, $iv);
	my $password_enutf8 = de_base64($password_base64);
	return $password_enutf8;
}

1;
