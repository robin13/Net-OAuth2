package Net::OAuth2::AccessToken;
use Moose;
use Moose::Util::TypeConstraints;

use JSON;
use Carp;
use URI::Escape;

has 'client'        => ( is => 'ro',    isa => 'Net::OAuth2::Client'    , required => 1,    );
has 'access_token'  => ( is => 'rw',    isa => 'Str'                                        );
has 'refresh_token' => ( is => 'rw',    isa => 'Str'                                        );
has 'token_type'    => ( is => 'rw',    isa => 'Str'                                        );
has 'expires_at'    => ( is => 'rw',    isa => 'Int'                                        );
has 'expires_in'    => ( is => 'rw',    isa => 'Int',
    trigger => sub{ $_[0]->expires_at( time() + $_[1] ) },  # Trust the expires_in more than expires_at
    # TODO: RCL 2011-09-05 Consider subtracting a safety-buffer here for data transfer time so that
    # we always refresh the token before it expires
    );

# True if the token in question has an expiration time.
sub expires {
    my $self = shift;
    return defined $self->expires_at;
}

sub request {
    my $self = shift;
    my ($method, $uri, $header, $content) = @_;
    my $request = HTTP::Request->new(
        $method => $self->client->site_url($uri), $header, $content
    );
    # We assume a bearer token type, but could extend to other types in the future
    my @bearer_token_scheme = split ':', $self->client->bearer_token_scheme;
    if (lc($bearer_token_scheme[0]) eq 'auth-header') {
        # Specs suggest using Bearer or OAuth2 for this value, but OAuth appears to be the de facto accepted value.
        # Going to use OAuth until there is wide acceptance of something else.
        my $auth_scheme = $self->token_type || $bearer_token_scheme[1] || 'OAuth';
        $request->headers->push_header(Authorization => $auth_scheme . " " . $self->valid_access_token);
    }
    elsif (lc($bearer_token_scheme[0]) eq 'uri-query') {
        my $query_param = $bearer_token_scheme[1] || 'oauth_token';
        $request->uri->query_form($request->uri->query_form, $query_param => $self->valid_access_token);
    }
    elsif (lc($bearer_token_scheme[0]) eq 'form-body') {
        croak "Embedding access token in request body is only valid for 'application/x-www-form-urlencoded' content type"
        unless $request->headers->content_type eq 'application/x-www-form-urlencoded';
        my $query_param = $bearer_token_scheme[1] || 'oauth_token';
        $request->add_content(
            ((defined $request->content and length $request->content) ?  "&" : "") .  
            uri_escape($query_param) . '=' . uri_escape($self->valid_access_token)
        );
    }
    return $self->client->request($request);
}

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
        "refresh_token=%s&" .
        "grant_type=refresh_token",
        $self->client->id,
        $self->client->secret,
        $self->refresh_token,
        );

    my $request = HTTP::Request->new(
        'POST' => $self->client->access_token_url(),
        $headers,
        $content,
    );
    my $response = $self->client->request( $request );
    if( not $response->is_success() ){
        croak( "Could not refresh access token" );
    }
    my $obj = eval{local $SIG{__DIE__}; decode_json($response->decoded_content)} || {};
    if( not $obj->{access_token} ){
        croak( "No access token found in data...\n" . $response->decoded_content );
    }
    foreach( qw/access_token token_type expires_in/ ){
        $self->$_( $obj->{$_} ) if $obj->{$_};
    }
    return $self->access_token;
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
    for (qw/access_token token_type refresh_token expires_in error error_desription error_uri state/) {
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
