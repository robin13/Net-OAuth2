#!/usr/bin/env perl
use strict;
use warnings;
use Dancer;
use Net::OAuth2::Client;
use HTML::Entities;

sub client {
	Net::OAuth2::Client->new(
		config->{client_id},
		config->{client_secret},
		site => 'https://launchpad.37signals.com/',
		authorize_path => '/authorization/new',
		access_token_path => '/authorization/token',
	)->web_server(redirect_uri => fix_uri(uri_for('/got/37signals')));
}

get '/get/37signals' => sub {
	redirect client->authorize_url;
};

get '/got/37signals' => sub {
	return wrap("Error: Missing access code") if (!defined params->{code});
	my $access_token =  client->get_access_token(params->{code});
	return wrap("Error: " . $access_token->to_string) if ($access_token->{error});
	my $content=<<EOT;
	<h2>Access token retrieved successfully!</h2>
EOT
	$content .= '<p>' . encode_entities($access_token->to_string) . '</p>';
	
	my $response = $access_token->get('/authorization.xml');
	if ($response->is_success) {
		$content.=<<EOT;
	<h2>Protected resource retrieved successfully!</h2>
EOT
		$content .= '<p>' . encode_entities($response->decoded_content) . '</p>';
	}
	else {
		$content .= '<p>Error: ' . $response->status_line . '</p>';
	}
	$content =~ s[\n][<br/>\n]g;

	return wrap($content);
};

sub fix_uri {
	(my $uri = shift) =~ s[/dispatch\.cgi][];
	return $uri;
}

sub wrap {
	my $content = shift;
	return <<EOT;
	<html>
	<head>
		<title>OAuth 2 Test</title>
		<style>
		h1 a {color: black; text-decoration:none}
		</style>
	</head>
	<body>
	<h1><a href='/'>OAuth 2 Test</a></h1>
	$content
	</body>
	</html>
EOT
}

get '/' => sub {
	my $content=<<EOT;
<p>Start here: <a href="/get/37signals">/get/37signals</a></p>
EOT
	return wrap($content);
};

dance;

