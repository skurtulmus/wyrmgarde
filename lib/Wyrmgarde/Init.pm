package Wyrmgarde::Init;

use strict;
use warnings;
use utf8;
use Wyrmgarde::DBUtils;
use Wyrmgarde::User;

my @set_tables = (
	q{
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	},
	q{
		CREATE TABLE IF NOT EXISTS roles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			role TEXT UNIQUE NOT NULL
		)
	},
	q{
		CREATE TABLE IF NOT EXISTS passwords (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			comment TEXT,
			password TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	},
	q{
		CREATE TABLE IF NOT EXISTS user_roles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			role_id INTEGER NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
		)
	},
	q{
		CREATE TABLE IF NOT EXISTS password_roles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			password_id INTEGER NOT NULL,
			role_id INTEGER NOT NULL,
			FOREIGN KEY (password_id) REFERENCES passwords(id) ON DELETE CASCADE,
			FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
		)
	}
);

my $set_roles = "INSERT OR IGNORE INTO roles (role) VALUES (?)";

sub init {
	my ($config, $dbh, $logger) = @_;
	my $admin_username = $config->{admin_username};
	my $admin_password = $config->{admin_password};
	my $admin_roles = $config->{admin_roles};
	my $user_roles = $config->{user_roles};
	Wyrmgarde::DBUtils::run_all($dbh, \@set_tables);
	$logger->info("Database: Application schema initialized");
	Wyrmgarde::DBUtils::run_bind($dbh, $set_roles, $admin_roles);
	Wyrmgarde::DBUtils::run_bind($dbh, $set_roles, $user_roles);
	$logger->info("Roles initialized: '$admin_roles,$user_roles'");
	Wyrmgarde::User::create("admin", $admin_password, $admin_roles, $dbh, $logger);
}

1;
