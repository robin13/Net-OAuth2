#!perl
use strict;
use warnings;

use Test::More tests => 1 + 2*4;
use Test::Mock::LWP::Dispatch;


$mock_ua->map(qr{.*}, sub {
	my $request = shift;
# https://graph.facebook.com/oauth/access_token....
# die $request->uri;

	my $response = HTTP::Response->new(200, 'OK');
	return $response;
});

BEGIN {
    use_ok( 'Net::OAuth2::Client' ) || BAIL_OUT('compilation'); 
}

use Data::Dumper qw(Dumper);
use YAML qw(LoadFile);
my $config = LoadFile('demo/config.yml');

#diag Dumper $config;
my %expected_result = (
	'facebook' => {
		authorize_url => 'https://graph.facebook.com/oauth/authorize?redirect_uri=http%3A%2F%2Fcpan.org%2Fgot%2Ffacebook&client_id=&type=web_server',
		access_token_url => 'https://graph.facebook.com/oauth/access_token?redirect_uri=http%3A%2F%2Fcpan.org%2Fgot%2Ffacebook&client_id=&client_secret=&type=web_server&code=',
	},
	'37signals' => {
		authorize_url => 'https://launchpad.37signals.com/authorization/new?redirect_uri=http%3A%2F%2Fcpan.org%2Fgot%2F37signals&client_id=&type=web_server',
		access_token_url => 'https://launchpad.37signals.com/authorization/token?redirect_uri=http%3A%2F%2Fcpan.org%2Fgot%2F37signals&client_id=&client_secret=&type=web_server&code=',
	},
);

foreach my $site_id (keys %{$config->{sites}}) {
	is (client($site_id)->authorize_url, $expected_result{$site_id}{authorize_url}, "authorize_url of $site_id");
	is (client($site_id)->access_token_url, $expected_result{$site_id}{access_token_url}, "access_token_url of $site_id");
	my $code = "abcd";
	my $access_token =  client($site_id)->get_access_token($code);
	isa_ok($access_token, 'Net::OAuth2::AccessToken');
	diag $access_token->to_string;
        my $response = $access_token->get($config->{sites}{$site_id}{protected_resource_path});
	ok($response->is_success, 'success');

        #$response = $access_token->get('/path?field=value');
	#ok($response->is_success, 'success');
}

sub client {
	my $site_id = shift;
	Net::OAuth2::Client->new(
		$config->{sites}{$site_id}{client_id},
		$config->{sites}{$site_id}{client_secret},
		site => $config->{sites}{$site_id}{site},
		authorize_path => $config->{sites}{$site_id}{authorize_path},
		access_token_path => $config->{sites}{$site_id}{access_token_path},
		access_token_method => $config->{sites}{$site_id}{access_token_method},
	)->web_server(redirect_uri => ("http://cpan.org/got/$site_id"));
}


