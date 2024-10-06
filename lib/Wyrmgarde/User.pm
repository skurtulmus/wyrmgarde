package Wyrmgarde::User;

use strict;
use warnings;
use Wyrmgarde::Hash;

sub check {
	my ($username, $dbh, $logger) = @_;
	my $sth;
	$sth = $dbh->prepare("SELECT username FROM users WHERE username = ?");
	$sth->execute($username);
	my $row = $sth->fetchrow_hashref;
	unless ($row) {
		$logger->info("User does not exist: '$username'");
		return 0;
	}
	return 1;
}

sub get {
	my ($dbh, $logger) = @_;
	my @users;
	my $sth;
	$sth = $dbh->prepare("SELECT username FROM users WHERE username != 'admin'");
	$sth->execute();
	while (my $row = $sth->fetchrow_hashref) {
		push @users, $row->{'username'};
	}
	return @users;
}

sub auth {
	my ($username, $password, $dbh, $logger) = @_;
	my $password_stored;
	my $sth;
	$sth = $dbh->prepare("SELECT password FROM users WHERE username = ?");
	$sth->execute($username);
	my $row = $sth->fetchrow_hashref;
	unless ($row) {
		$logger->info("User does not exist: '$username'");
		return 0;
	}
	$password_stored = $row->{password};
	my $value = Wyrmgarde::Hash::verify($password, $password_stored);
	unless ($value == 1) {
		$logger->info("Invalid password for user: '$username'");
		return 0;
	}
	$logger->info("Valid password for user: '$username'");
	return 1;
}

sub create {
	my ($username, $password, $roles, $dbh, $logger) = @_;
	my $sth;
	$sth = $dbh->prepare("SELECT id FROM users WHERE username = ?");
	$sth->execute($username);
	my $row = $sth->fetchrow_hashref;
	if ($row) {
		$logger->info("User '$username' not created: User already exists");
		return 2;
	}
	my $hash = Wyrmgarde::Hash::create($password);
	$sth = $dbh->prepare("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)");
	$sth->execute($username, $hash);
	$logger->info("User created: '$username'");
	$sth = $dbh->prepare("SELECT id FROM users WHERE username = ?");
	$sth->execute($username);
	$row = $sth->fetchrow_hashref;
	my $user_id = $row->{id};
	my @roles = split /,/, $roles;
	my @role_ids;
	foreach my $role (@roles) {
		$sth = $dbh->prepare("SELECT id FROM roles WHERE role = ?");
		$sth->execute($role);
		my $row = $sth->fetchrow_hashref;
		push @role_ids, $row->{'id'};
	}
	foreach my $role_id (@role_ids) {
		$sth = $dbh->prepare("INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)");
		$sth->execute($user_id, $role_id);
	}
	$logger->info("Roles added for user '$username': '$roles'");
	return 1;
}

sub delete {
	my ($username, $dbh, $logger) = @_;
	my $sth;
	$sth = $dbh->prepare("SELECT id FROM users WHERE username = ?");
	$sth->execute($username);
	my $row = $sth->fetchrow_hashref;
	unless ($row) {
		$logger->info("User '$username' not deleted: User does not exist");
		return 2;
	}
	my $user_id = $row->{id};
	$sth = $dbh->prepare("DELETE FROM users WHERE username = ?");
	$sth->execute($username);
	$sth = $dbh->prepare("Delete FROM user_roles WHERE user_id = ?");
	$sth->execute($user_id);
	$logger->info("User deleted: '$username'");
	return 1;
}

sub edit_username {
	my ($username, $new_username, $dbh, $logger) = @_;
	my $sth;
	$sth = $dbh->prepare("UPDATE users SET username = ? WHERE username = ?");
	my $row = $sth->execute($new_username, $username);
	$logger->info("Username for '$username' changed to: '$new_username'");
	return 1;
}

sub edit_password {
	my ($username, $new_password, $dbh, $logger) = @_;
	my $sth;
	my $new_password_stored = Wyrmgarde::Hash::create($new_password);
	return 0 unless $new_password_stored;
	$sth = $dbh->prepare("UPDATE users SET password = ? WHERE username = ?");
	my $row = $sth->execute($new_password_stored, $username);
	return 0 unless $row;
	$logger->info("Password changed for '$username'");
	return 1;
}

sub all_roles {
	my ($dbh) = @_;
	my $sth;
	my @roles;
	$sth = $dbh->prepare("SELECT role FROM roles");
	$sth->execute();
	while (my $row = $sth->fetchrow_hashref()) {
		push @roles, $row->{'role'};
	}
	return @roles;
}

sub user_roles {
	my ($dbh, $username) = @_;
	my @role_ids;
	my @roles;
	my $sth;
	$sth = $dbh->prepare("SELECT id FROM users WHERE username = ?");
	$sth->execute($username);
	my $row = $sth->fetchrow_hashref;
	my $user_id = $row->{id};
	$sth = $dbh->prepare("SELECT role_id FROM user_roles WHERE user_id = ?");
	$sth->execute($user_id);
	while (my $row = $sth->fetchrow_hashref()) {
		push @role_ids, $row->{'role_id'};
	}
	foreach my $id (@role_ids) {
		$sth = $dbh->prepare("SELECT role FROM roles WHERE id = ?");
		$sth->execute($id);
		my $row = $sth->fetchrow_hashref;
		push @roles, $row->{'role'};
	}
	return @roles;
}

sub edit_roles {
	my ($username, $new_roles, $dbh, $logger) = @_;
	my $sth;
	my @new_roles = split /,/, $new_roles;
	my @all_roles = all_roles($dbh);
	my @user_roles = user_roles($dbh, $username);
	$sth = $dbh->prepare("SELECT id FROM users WHERE username = ?");
	$sth->execute($username);
	my $row = $sth->fetchrow_hashref;
	my $user_id = $row->{id};
	foreach my $role (@all_roles) {
		if (grep { $_ eq $role } @new_roles) {
			unless (grep { $_ eq $role } @user_roles) {
				$sth = $dbh->prepare("SELECT id FROM roles WHERE role = ?");
				$sth->execute($role);
				my $row = $sth->fetchrow_hashref;
				my $role_id = $row->{id};
				$sth = $dbh->prepare("INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)");
				$sth->execute($user_id, $role_id);
			}
		} else {
			if (grep { $_ eq $role } @user_roles) {
				$sth = $dbh->prepare("SELECT id FROM roles WHERE role = ?");
				$sth->execute($role);
				my $row = $sth->fetchrow_hashref;
				my $role_id = $row->{id};
				$sth = $dbh->prepare("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?");
				$sth->execute($user_id, $role_id);
			}
		}
	}
	$logger->info("Roles updated for '$username': $new_roles");
	return 1;
}

1;
