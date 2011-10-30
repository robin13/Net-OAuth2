package Net::OAuth2::Profile::Base;
use Moose::Role;
use Carp;
use JSON;
use HTTP::Request::Common;
use MooseX::Types::URI qw/Uri/;

has 'user_agent'        => ( is => 'ro', isa => 'LWP::UserAgent', required => 1              );
has 'interactive' => ( is => 'ro', isa => 'Bool', required => 1, default => 0 );

sub authorize_url {
    my $self = shift;
    return $self->client->authorize_url($self->authorize_params(@_));
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
