package Net::OAuth2::Profile::WebServer;
use Moose;

with 'Net::OAuth2::Profile::Base';
use Carp;
use Net::OAuth2::AccessToken;
use HTTP::Request::Common;

has 'redirect_uri'  => ( is => 'ro', isa => 'Url', required => 1 );
has 'grant_type'    => ( is => 'ro', isa => 'Str', required => 1, default => 'authorization_code' );

before 'get_access_token' => sub{
    if( not $_[1] ){
        croak( "Cannot reasonably try to get an access token without an access code...\n" );
    }
};

sub authorize_params {
    my $self = shift;
    my %options             =   $self->generic_authorize_params(@_);
    $options{response_type} =   'code';
    $options{redirect_uri}  ||= $self->redirect_uri;
    # legacy for pre v2.09 (37Signals)
    $options{type} = 'web_server';
    return %options;
}

sub access_token_params {
    my $self = shift;
    my $code = shift;
    my %options = $self->generic_access_token_params($code, @_);
    $options{code}          =   $code;
    $options{grant_type}    ||= $self->grant_type;
    $options{redirect_uri}  ||= $self->redirect_uri;
    # legacy for pre v2.09 (37Signals)
    $options{type}          =   'web_server';
    return %options;
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
