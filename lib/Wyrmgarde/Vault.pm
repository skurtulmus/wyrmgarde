package Wyrmgarde::Vault;

use strict;
use warnings;
use Wyrmgarde::Crypt;

sub access {
	my ($username, $dbh, $logger) = @_;
	my $sth;
	my $params;
	my @role_ids;
	my @password_ids;
	my @passwords;
	$sth = $dbh->prepare("SELECT id FROM users WHERE username = ?");
	$sth->execute($username);
	my $row = $sth->fetchrow_hashref;
	my $user_id = $row->{id};
	$sth = $dbh->prepare("SELECT role_id FROM user_roles WHERE user_id = ?");
	$sth->execute($user_id);
	while (my $row = $sth->fetchrow_hashref()) {
		push @role_ids, $row->{'role_id'};
	}
	$params = join(", ", ("?") x @role_ids);
	$sth = $dbh->prepare("SELECT password_id FROM password_roles WHERE role_id IN ($params)");
	$sth->execute(@role_ids);
	while (my $row = $sth->fetchrow_hashref()) {
		push @password_ids, $row->{'password_id'};
	}
	$params = join(", ", ("?") x @password_ids);
	$sth = $dbh->prepare("SELECT name FROM passwords WHERE id IN ($params)");
	$sth->execute(@password_ids);
	while (my $row = $sth->fetchrow_hashref()) {
		push @passwords, $row->{'name'};
	}
	return @passwords;
}

sub insert {
	my ($name, $comment, $password, $roles, $key, $dbh, $logger) = @_;
	my $sth;
	$sth = $dbh->prepare("SELECT id FROM passwords WHERE name = ?");
	$sth->execute($name);
	my $row = $sth->fetchrow_hashref;
	if ($row) {
		$logger->info("Password '$name' not created: Name already exists");
		return 2;
	}
	my $encrypted = Wyrmgarde::Crypt::encrypt($password, $key);
	$sth = $dbh->prepare("INSERT OR IGNORE INTO passwords (name, comment, password) VALUES (?, ?, ?)");
	$sth->execute($name, $comment, $encrypted);
	$logger->info("Password created: '$name'");
	$sth = $dbh->prepare("SELECT id FROM passwords WHERE name = ?");
	$sth->execute($name);
	$row = $sth->fetchrow_hashref;
	my $password_id = $row->{id};
	my @roles = split /,/, $roles;
	my @role_ids;
	foreach my $role (@roles) {
		$sth = $dbh->prepare("SELECT id FROM roles WHERE role = ?");
		$sth->execute($role);
		my $row = $sth->fetchrow_hashref;
		push @role_ids, $row->{'id'};
	}
	foreach my $role_id (@role_ids) {
		$sth = $dbh->prepare("INSERT OR IGNORE INTO password_roles (password_id, role_id) VALUES (?, ?)");
		$sth->execute($password_id, $role_id);
	}
	$logger->info("Roles added for password '$name': '$roles'");
	return 1;
}

1;
