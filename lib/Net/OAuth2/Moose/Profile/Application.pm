package Net::OAuth2::Profile::Application;
use Moose;

with 'Net::OAuth2::Profile::Base';
use Carp;
use Net::OAuth2::AccessToken;
use HTTP::Request::Common;

has '+interactive' => ( default => 1 );

around 'get_access_token' => sub{
    my $orig = shift;
    my $self = shift;
    my $code = shift;
    if( not $code ){
        printf "Please authorize your application with this URL\n%s\n",
            $self->_authorize_uri();
        if( not $self->interactive ){
            exit;
        }
        print "Code: ";
        $code = <STDIN>;
        chomp( $code );
    }
    return $self->$orig( $code );
};

sub authorize_params {
    my $self = shift;
    my %options = $self->generic_authorize_params(@_);
    $options{response_type}   = 'code';
    $options{redirect_uri}    = 'urn:ietf:wg:oauth:2.0:oob';
    return %options;
}

sub access_token_params {
    my %options = @_;  
    $options{client_id}         = $self->client_id     unless defined $options{client_id};
    $options{client_secret}     = $self->client_secret unless defined $options{client_secret};
    if( $self->profile eq 'webserver' ){
        $options{grant_type}    ||= $self->grant_type;
        $options{redirect_uri}  ||= $self->redirect_uri;
        # legacy for pre v2.09 (37Signals)
        $options{type}          =   'web_server';
    } else {
        $options{grant_type}        = 'authorization_code';  
        $options{redirect_uri}      = 'urn:ietf:wg:oauth:2.0:oob';
    }
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
