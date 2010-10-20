#!/usr/bin/perl
use strict;
use warnings;
use Plack::Server::CGI;
use Plack::Util;

my $psgi = '/path/to/app.psgi';
my $app = Plack::Util::load_psgi($psgi);
Plack::Server::CGI->new->run($app);
