package Net::OAuth2::Profile::Base;
use Moose::Role;
use Carp;
use JSON;
use HTTP::Request::Common;
use MooseX::Types::URI qw/Uri/;

has 'client' => ( is => 'ro', isa => 'Net::OAuth2::Client', required => 1 );

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
    if( not $response->is_success ){
        croak( "Fetch of access token failed: " . $response->status_line . ": " . $response->decoded_content );
    }
    my $res_params = _parse_json($response->decoded_content);
    $res_params = _parse_query_string($response->decoded_content) unless defined $res_params;
    if( not defined $res_params ){
        croak( "Unable to parse access token response '".substr($response->decoded_content, 0, 64)."'" );
    }
    $res_params->{client} = $self->client;
    return Net::OAuth2::AccessToken->new(%$res_params);
}

sub authorize_url {
    my $self = shift;
    return $self->client->authorize_url($self->authorize_params(@_));
}

sub generic_authorize_params {
    my $self = shift;
    my %options = @_;
    $options{scope}       = $self->client->scope  unless defined $options{scope};
    $options{client_id}   = $self->client->id     unless defined $options{client_id};
    return %options;
}

sub access_token_url {
    my $self = shift;
    return $self->client->access_token_url($self->access_token_params(@_));
}

sub generic_access_token_params {
    my $self = shift;
    my $code = shift;
    my %options = @_;  
    $options{client_id}     = $self->client->id     unless defined $options{client_id};
    $options{client_secret} = $self->client->secret unless defined $options{client_secret};
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
