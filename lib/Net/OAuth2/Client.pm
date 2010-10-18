package Net::OAuth2::Client;
use warnings;
use strict;
use base qw(Class::Accessor);
__PACKAGE__->mk_accessors(qw/id secret user_agent options web_server site/);
use LWP::UserAgent;
use URI;
use URI::QueryParams;

sub new {
  my $class = shift;
  my %opts = @_;
  $opts{user_agent} ||= LWP::UserAgent->new;
  _ensure_uri_object($opts{site}) if defined $opts{site};
  my $self = bless %opts, $class;
  return $self;
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
  my %params = @_;
  my $path = $self->{"${thing}_url"} || $self->{"${thing}_path"} || "/oauth/${thing}";
  my $url;
  if (defined $self->{site}) {
    $url = URI->new_abs($path, $self->{site});
  }
  else {
    $url = URI->new($path);
  }
  if (@_) {
    $url->query_form({%{$url->query_form}, %params});
  }
  return $url;
}

=head1 LICENSE AND COPYRIGHT

Copyright 2010 Keith Grennan.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut


1;