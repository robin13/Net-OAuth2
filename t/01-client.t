#!perl
use strict;
use warnings;

use Test::More;
use Test::Mock::LWP::Dispatch;
use Test::NoWarnings;

my %expected_result = (
	'facebook' => {
		authorize_url => [
                                 'https://graph.facebook.com/oauth/authorize?',
                                 'redirect_uri=http%3A%2F%2Fcpan.org%2Fgot%2Ffacebook',
                                 'client_id=',
                                 'type=web_server'],
		access_token_url => [
                                 'https://graph.facebook.com/oauth/access_token',
                                 'redirect_uri=http%3A%2F%2Fcpan.org%2Fgot%2Ffacebook',
                                 'client_id=',
                                 'client_secret=',
                                 'type=web_server',
                                 'code='],
	},
	'37signals' => {
		authorize_url => [
                                 'https://launchpad.37signals.com/authorization/new',
                                 'redirect_uri=http%3A%2F%2Fcpan.org%2Fgot%2F37signals',
                                 'client_id=',
                                 'type=web_server'],
		access_token_url => [
                                 'https://launchpad.37signals.com/authorization/token',
                                 'redirect_uri=http%3A%2F%2Fcpan.org%2Fgot%2F37signals',
                                 'client_id=',
                                 'client_secret=',
                                 'type=web_server',
                                 'code='],
	},
      'mixi' => {
              authorize_url => [
                                'https://mixi.jp/connect_authorize.pl',
                                'redirect_uri=http%3A%2F%2Fcpan.org%2Fgot%2Fmixi',
                                'client_id=',
                                'type=web_server'],
              access_token_url => [
                                'https://secure.mixi-platform.com/2/token',
                                'redirect_uri=http%3A%2F%2Fcpan.org%2Fgot%2Fmixi',
                                'client_secret=',
                                'client_id=',
                                'type=web_server',
                                'code='],
      },
);
my %params = (
	'facebook'  => [
	    'scope'	    => 'read-write',
	    ],
        '37signals' => [ 
	    ],
	'mixi' => [
	    'scope'	    => 'r_profile',
	    ],
);


my @sites = keys %expected_result;
my $tests = 1; # no warnings;
foreach my $site_id (@sites) {
    $tests += @{ $expected_result{$site_id}{authorize_url} } + @{ $expected_result{$site_id}{access_token_url} } + 3;
}
plan tests => $tests; 

$mock_ua->map(qr{.*}, sub {
    my $request = shift;
# https://graph.facebook.com/oauth/access_token....
# die $request->uri;
    my $response = HTTP::Response->new(200, 'OK');
    if (defined $request->content and $request->content =~ /\b(code|refresh_token)=/) {
	$response->add_content('{"access_token": "abcd","token_type":"bearer","refresh_token":"11_refresh_11"}');
    }
    return $response;
});


use Net::OAuth2::Moosey::Client;

use YAML qw(LoadFile);
my $config = LoadFile('demo/config.yml');

foreach my $site_id (@sites) {
    my $client = client( $site_id );
    
    my $code = "abcd";
    my $access_token =  client($site_id)->access_token->valid_access_token( @{$params{$site_id}});
    
    #	diag $access_token->to_string;
    my $response = client($site_id)->get($config->{sites}{$site_id}{protected_resource_path});
    ok($response->is_success, 'success');

    $response = client($site_id)->get('/path?field=value');
    ok($response->is_success, 'success');
}

sub client {
    my $site_id = shift;
    Net::OAuth2::Moosey::Client->new( %{ $config->{sites}{$site_id} },
	redirect_uri		=> "http://cpan.org/got/$site_id",
	access_token_method	=> 'GET',
	profile			=> 'webserver',
	);
}


