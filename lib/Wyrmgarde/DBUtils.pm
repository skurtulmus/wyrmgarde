package Wyrmgarde::DBUtils;

use strict;
use warnings;
use utf8;
use DBI;

my $dbh;

sub connect {
	my ($config, $logger) = @_;
	my $database = $config->{database};
	$dbh = DBI->connect("dbi:SQLite:dbname=$database", "", "", { RaiseError => 1, PrintError => 0 }) or do {
		$logger->fatal("Database connection failed: $database");
		exit 1;
	};
	$logger->info("Database connected: $database");
	return $dbh;
}

sub run_all {
	my ($dbh, $commands_ref) = @_;
	my @commands = @{$commands_ref};
	foreach my $st (@commands) {
		my $sth = $dbh->prepare($st);
		$sth->execute();
	}
}

sub run_bind {
	my ($dbh, $command, $list) = @_;
	my @list = split /,/, $list;
	foreach my $item (@list) {
		my $sth = $dbh->prepare($command);
		$sth->execute($item);
	}
}

sub disconnect {
	my ($dbh, $logger) = @_;
	$dbh->disconnect;
	$logger->info("Database disconnected");
}

1;
