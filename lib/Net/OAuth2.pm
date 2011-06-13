package Net::OAuth2;

use warnings;
use strict;

=head1 NAME

Net::OAuth2 - OAuth 2.0 for Perl

=cut

our $VERSION = '0.07';

=head1 SYNOPSIS

  # This example is simplified for illustrative purposes, see the complete code in /demo

  use Dancer;
  use Net::OAuth2::Client;

  sub client {
  	Net::OAuth2::Client->new(
  		config->{client_id},
  		config->{client_secret},
  		site => 'https://graph.facebook.com',
  	)->web_server(
  	  redirect_uri => uri_for('/auth/facebook/callback')
  	);
  }

  # Send user to authorize with service provider
  get '/auth/facebook' => sub {
  	redirect client->authorize_url;
  };

  # User has returned with '?code=foo' appended to the URL.
  get '/auth/facebook/callback' => sub {
  
  	# Use the auth code to fetch the access token
  	my $access_token =  client->get_access_token(params->{code});
	
  	# Use the access token to fetch a protected resource
  	my $response = $access_token->get('/me');
	
  	# Do something with said resource...
	
  	if ($response->is_success) {
  	  return "Yay, it worked: " . $response->decoded_content;
  	}
  	else {
  	  return "Error: " . $response->status_line;
  	}
  };

  dance;

=head1 RESOURCES

View Source on GitHub: http://github.com/keeth/Net-OAuth2

Report Issues on GitHub: http://github.com/keeth/Net-OAuth2/issues

Download from CPAN: http://search.cpan.org/perldoc?Net::OAuth2

=head1 AUTHOR

Keith Grennan, C<< <kgrennan at cpan.org> >>

=head1 ACKNOWLEDGEMENTS

Net::OAuth2 was initially ported from the oauth2 ruby gem by Michael Bleigh

=head1 LICENSE AND COPYRIGHT

Copyright 2010 Keith Grennan.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

1; # End of Net::OAuth2
