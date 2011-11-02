package Net::OAuth2::Moosey::AccessToken;
use Moose;
use Moose::Util::TypeConstraints;

use JSON;
use Carp;
use URI::Escape;
use YAML qw/LoadFile DumpFile Dump/;
use MooseX::Types::URI qw(Uri FileUri DataUri);

has 'user_agent'        => ( is => 'ro', isa => 'LWP::UserAgent', required => 1              );
has 'client_id'         => ( is => 'ro', isa => 'Str',                                       );
has 'client_secret'     => ( is => 'ro', isa => 'Str',                                       );
has 'access_token_url'  => ( is => 'ro', isa => Uri, required => 1                          );
#TODO: RCL 2011-10-03  has client_id, client_secret, access_token_url
has 'access_token'      => ( is => 'rw', isa => 'Str'                                        );
has 'refresh_token'     => ( is => 'rw', isa => 'Str'                                        );
has 'token_store'       => ( is => 'rw', isa => 'Str'                                        );
has 'token_type'        => ( is => 'rw', isa => 'Str'                                        );
has 'expires_at'        => ( is => 'rw', isa => 'Int'                                        );
has 'expires_in'        => ( is => 'rw', isa => 'Int',
    trigger => sub{ $_[0]->expires_at( time() + $_[1] ) },  # Trust the expires_in more than expires_at
    # TODO: RCL 2011-09-05 Consider subtracting a safety-buffer here for data transfer time so that
    # we always refresh the token before it expires
    );


# Returns a valid access token (refreshing if necessary)
sub valid_access_token {
    my $self = shift;
    if( $self->access_token and $self->expires_at and $self->expires_at > time() ){
        return $self->access_token;
    }
    if( not $self->refresh_token ){
	croak( "Cannot refresh access_token without refresh_token" );
    }

    # This is knitted specifically to Googles OAuth2 implementation - is it universal?
    my $headers = HTTP::Headers->new( Content_Type  => 'application/x-www-form-urlencoded'  );
    my $content = sprintf( "client_id=%s&" .
        "client_secret=%s&" .
        "refresh_token=refresh_token" .
        "grant_type=%s",
        $self->client_id,
        $self->client_secret,
        $self->refresh_token,
        );

    my $request = HTTP::Request->new(
        'POST' => $self->access_token_url,
        $headers,
        $content,
    );
    my $response = $self->user_agent->request( $request );
    if( not $response->is_success() ){
        croak( "Could not refresh access token: " . $response->code );
    }
    my $obj = eval{local $SIG{__DIE__}; decode_json($response->decoded_content)} || {};
    if( not $obj->{access_token} ){
        croak( "No access token found in data...\n" . $response->decoded_content );
    }
    foreach( qw/access_token token_type expires_in/ ){
        $self->$_( $obj->{$_} ) if $obj->{$_};
    }
    $self->sync_with_store();
    return $self->access_token;
}



sub to_string {
    my $self = shift;
    my %hash;
    for (qw/access_token token_type refresh_token expires_in expires_at error error_desription error_uri state/) {
        $hash{$_} = $self->{$_} if defined $self->{$_};
    }
    return encode_json(\%hash);
}

sub sync_with_store {
    my $self = shift;
    if( not $self->token_store ){
        print "No token_store defined\n";
        return;
    }
    my $data;
    if( -f $self->token_store ){
        $data = LoadFile( $self->token_store );
    }
    if( my $old_node = $data->{ $self->client_id } ){
        if( $old_node->{expires_at} 
            and time() < $old_node->{expires_at} 
            and ( 
                not $self->expires_at or $self->expires_at < $old_node->{expires_at} ) )
        {
            $self->expires_at( $old_node->{expires_at} );
            $self->access_token( $old_node->{access_token} )    if $old_node->{access_token};
        }
        $self->refresh_token( $old_node->{refresh_token} ) if( not $self->refresh_token and $old_node->{refresh_token} );
    }
    foreach( qw/refresh_token access_token expires_at/ ){
        $data->{ $self->client_id }->{$_} = $self->$_ if $self->$_;
    }
    DumpFile( $self->token_store, $data );
}

=head1 NAME

Net::OAuth2::Moosey::AccessToken - OAuth Access Token

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
