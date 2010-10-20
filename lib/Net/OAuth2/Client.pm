package Net::OAuth2::Client;
use warnings;
use strict;
use base qw(Class::Accessor::Fast);
__PACKAGE__->mk_accessors(qw/id secret user_agent site/);
use LWP::UserAgent;
use URI;
use Net::OAuth2::Profile::WebServer;

sub new {
  my $class = shift;
  my $client_id = shift;
  my $client_secret = shift;
  my %opts = @_;
  $opts{user_agent} ||= LWP::UserAgent->new;
  _ensure_uri_object($opts{site}) if defined $opts{site};
  $opts{id} = $client_id;
  $opts{secret} = $client_secret;
  my $self = bless \%opts, $class;
  return $self;
}

sub web_server {
	my $self = shift;
	return Net::OAuth2::Profile::WebServer->new(client => $self, @_);
}

sub _ensure_uri_object {
    $_[0] = UNIVERSAL::isa($_[0], 'URI') ? $_[0] : URI->new($_[0]);
}

sub request {
  my $self = shift;
  my $response = $self->user_agent->request(@_);
}

sub authorize_url {
  return shift->_make_url("authorize", @_);
}

sub access_token_url {
  return shift->_make_url("access_token", @_);
}

sub _make_url {
  my $self = shift;
  my $thing = shift;
  my $path = $self->{"${thing}_url"} || $self->{"${thing}_path"} || "/oauth/${thing}";
  return $self->site_url($path, @_);
}

sub site_url {
  my $self = shift;
  my $path = shift;
  my %params = @_;
  my $url;
  if (defined $self->{site}) {
    $url = URI->new_abs($path, $self->{site});
  }
  else {
    $url = URI->new($path);
  }
  if (@_) {
    $url->query_form({%{$url->query_form || {}}, %params});
  }
  return $url;
}

=head1 NAME

Net::OAuth2::Client - OAuth Client

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
