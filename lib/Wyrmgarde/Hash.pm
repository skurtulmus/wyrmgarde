package Wyrmgarde::Hash;

use strict;
use warnings;
use utf8;
use Encode;
use Bytes::Random::Secure::Tiny;
use Crypt::Eksblowfish::Bcrypt qw(bcrypt_hash en_base64 de_base64);

sub create {
	my ($password_rawtxt) = @_;
	my $rng = Bytes::Random::Secure::Tiny->new;
	my $salt = $rng->bytes(16);
	my $password_enutf8 = encode('UTF-8', $password_rawtxt);
	my $password_base64 = en_base64($password_enutf8);
	my $password_hashed = bcrypt_hash({
		key_nul => 1,
		cost => 8,
		salt => $salt,
	}, $password_base64);
	my $octets = $salt . $password_hashed;
	my $password_stored = en_base64($octets);
	return $password_stored;
}

sub verify {
	my ($password_rawtxt, $password_stored) = @_;
	my $octets = de_base64($password_stored);
	my $salt = substr($octets,0,16);
	my $password_hash02 = substr($octets,16);
	my $password_enutf8 = encode('UTF-8', $password_rawtxt);
	my $password_base64 = en_base64($password_enutf8);
	my $password_hash01 = bcrypt_hash({
		key_nul => 1,
		cost => 8,
		salt => $salt,
	}, $password_base64);
	if ($password_hash01 eq $password_hash02) {
		return 1;
	} else {
		return 0;
	}
}

1;
