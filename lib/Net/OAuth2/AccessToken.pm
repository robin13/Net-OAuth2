package Net::OAuth2::AccessToken;
use warnings;
use strict;
use base qw(Class::Accessor::Fast);
use JSON;
__PACKAGE__->mk_accessors(qw/client access_token refresh_token expires_in expires_at scope/);

sub new {
  my $class = shift;
  my %opts = @_;
  my $self = bless \%opts, $class;
  if (defined $self->{expires_in} and $self->{expires_in} =~ /^\d+$/) {
    $self->expires_at(time() + $self->{expires_in});
  }
  else {
    delete $self->{expires_in};
  }
  return $self;
}

# True if the token in question has an expiration time.
sub expires {
  my $self = shift;
  return defined $self->expires_at;
}

sub request {
  my $self = shift;
  my ($method, $uri, $header, $content) = @_;
  return $self->client->request(HTTP::Request->new(
    $method => $self->client->site_url($uri, $self->client->access_token_param => $self->access_token), $header, $content
  ));
}

sub get {
	return shift->request('GET', @_);
}

sub post {
	return shift->request('POST', @_);
}

sub delete {
	return shift->request('DELETE', @_);
}

sub put {
	return shift->request('PUT', @_);
}

sub to_string {
	my $self = shift;
	my %hash;
	for (qw/access_token refresh_token expires_in scope error error_desription error_uri state/) {
		$hash{$_} = $self->{$_} if defined $self->{$_};
	}
	return encode_json(\%hash);
}

=head1 NAME

Net::OAuth2::AccessToken - OAuth Access Token

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
