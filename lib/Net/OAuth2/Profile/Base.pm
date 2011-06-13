package Net::OAuth2::Profile::Base;
use warnings;
use strict;
use base qw(Class::Accessor::Fast);
__PACKAGE__->mk_accessors(qw/client/);

sub new {
  my $class = shift;
  my %opts = @_;
  my $self = bless \%opts, $class;
  return $self;
}

sub authorize_url {
  my $self = shift;
  return $self->client->authorize_url($self->authorize_params(@_));
}

sub authorize_params {
  my $self = shift;
  my %options = @_;
  $options{scope} = $self->client->scope unless defined $options{scope};
  $options{client_id} = $self->client->id unless defined $options{client_id};
  return %options;
}

sub access_token_url {
  my $self = shift;
  return $self->client->access_token_url($self->access_token_params(@_));
}

sub access_token_params {
  my $self = shift;
  my $code = shift;
  my %options = @_;  
  $options{client_id} = $self->client->id unless defined $options{client_id};
  $options{client_secret} = $self->client->secret unless defined $options{client_secret};
  return %options;
}

=head1 NAME

Net::OAuth2::Profile::Base - OAuth Profile Base Class

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
