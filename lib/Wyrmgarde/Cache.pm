package Wyrmgarde::Cache;

use strict;
use warnings;
use utf8;

sub control {
	my ($app) = @_;
	my $logger = $app->log;

	$app->hook(after_dispatch => sub {
		my $c = shift;
		if ($c->session('username')) {
			$c->res->headers->cache_control('no-store, must-revalidate');
		}
	});
}

1;
