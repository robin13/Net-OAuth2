package Net::OAuth2::Profile::Application;
use Moose;

with 'Net::OAuth2::Profile::Base';
use Carp;
use Net::OAuth2::AccessToken;
use HTTP::Request::Common;

before 'get_access_token' => sub{
    if( not $_[1] ){
        printf "Please authorize your application with this URL, and start again with the parameter access_code\n%s\n",
        $_[0]->_authorize_uri();
        exit;
    }
};

sub authorize_params {
    my $self = shift;
    my %options = $self->generic_authorize_params(@_);
    $options{response_type}   = 'code';
    $options{redirect_uri}    = 'urn:ietf:wg:oauth:2.0:oob';
    return %options;
}

sub access_token_params {
    my $self = shift;
    my $code = shift;
    my %options = $self->generic_access_token_params($code, @_);
    $options{code}            = $code;
    $options{grant_type}      = 'authorization_code';  
    $options{redirect_uri}    = 'urn:ietf:wg:oauth:2.0:oob';
    return %options;
}

sub _authorize_uri {
    my $self = shift;
    my %req_params = @_;

    my $request = HTTP::Request->new(
            GET => $self->client->authorize_url($self->authorize_params( %req_params )),
    );
    return $request->uri();
}

=head1 NAME

Net::OAuth2::Profile::Application - OAuth Application Profile

=head1 SEE ALSO

L<Net::OAuth>

=head1 LICENSE AND COPYRIGHT

Copyright 2011 Robin Clarke

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut


1;
