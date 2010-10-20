#!/usr/bin/perl
use strict;
use warnings;
use lib qw(
	.
	/home/kg23/local/share/perl/5.10
	/home/kg23/local/share/perl/5.10.0
	/home/kg23/local/lib/perl/5.10
	/home/kg23/local/lib/perl/5.10.0
	);

use Plack::Server::CGI;
use Plack::Util;

my $psgi = '/home/kg23/oauth.kg23.com/app.psgi';
my $app = Plack::Util::load_psgi($psgi);
Plack::Server::CGI->new->run($app);
