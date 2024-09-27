package Wyrmgarde::Config;

use strict;
use warnings;
use utf8;
use Config::Tiny;

sub load {
	my ($file, $logger) = @_;
	my $config = Config::Tiny->read($file);
	unless ($config) {
		$logger->fatal("Unable to read configuration file '$file': $!");
		exit 1;
	}
	$logger->info("Configuration loaded: $file");
	return $config;
}

1;
