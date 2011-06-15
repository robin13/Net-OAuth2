package Net::OAuth2::Profile::WebServer;
use warnings;
use strict;
use base qw(Net::OAuth2::Profile::Base);
use JSON;
use URI;
use Net::OAuth2::AccessToken;
use HTTP::Request::Common;

__PACKAGE__->mk_accessors(qw/redirect_uri grant_type/);

sub authorize_params {
  my $self = shift;
  my %options = $self->SUPER::authorize_params(@_);
  $options{response_type} = 'code';
  $options{redirect_uri} = $self->redirect_uri if defined $self->redirect_uri;
  # legacy for pre v2.09 (37Signals)
  $options{type} = 'web_server';
  return %options;
}

sub get_access_token {
  my $self = shift;
  my $code = shift;
  my %req_params = @_;

  my $request;
  if ($self->client->access_token_method eq 'POST') {
    $request = POST($self->client->access_token_url(), {$self->access_token_params($code, %req_params)});
  } else {
    $request = HTTP::Request->new(
      $self->client->access_token_method => $self->client->access_token_url($self->access_token_params($code, %req_params))
  );
  }
  my $response = $self->client->request($request);
  die "Fetch of access token failed: " . $response->status_line . ": " . $response->decoded_content unless $response->is_success;
  my $res_params = _parse_json($response->decoded_content);
  $res_params = _parse_query_string($response->decoded_content) unless defined $res_params;
  die "Unable to parse access token response '".substr($response->decoded_content, 0, 64)."'" unless defined $res_params;
  $res_params->{client} = $self->client;
  return Net::OAuth2::AccessToken->new(%$res_params);
}

sub access_token_params {
  my $self = shift;
  my $code = shift;
  my %options = $self->SUPER::access_token_params($code, @_);
  $options{code} = $code;
  $options{grant_type} = 'authorization_code';
  $options{redirect_uri} = $self->redirect_uri if defined $self->redirect_uri;
  # legacy for pre v2.09 (37Signals)
  $options{type} = 'web_server';
  return %options;
}

sub _parse_query_string {
  my $str = shift;
  my $uri = URI->new;
  $uri->query($str);
  return {$uri->query_form};
}

sub _parse_json {
  my $str = shift;
  my $obj = eval{local $SIG{__DIE__}; decode_json($str)};
  return $obj;
}

=head1 NAME

Net::OAuth2::Profile::WebServer - OAuth Web Server Profile

=head1 SEE ALSO

L<Net::OAuth>

=head1 LICENSE AND COPYRIGHT

Copyright 2010 Keith Grennan.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut


1;
