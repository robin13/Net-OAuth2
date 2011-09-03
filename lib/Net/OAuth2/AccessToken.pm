package Net::OAuth2::AccessToken;
use warnings;
use strict;
use base qw(Class::Accessor::Fast);
use JSON;
use Carp;
use URI::Escape;
__PACKAGE__->mk_accessors(qw/client access_token refresh_token expires_in expires_at scope token_type/);

sub new {
    my $class = shift;
    my %opts = @_;
    my $self = bless \%opts, $class;
    if (defined $self->{expires_in} and $self->{expires_in} =~ /^\d+$/) {
        $self->expires_at(time() + $self->{expires_in});
    }
    else {
        delete $self->{expires_in};
    }
    return $self;
}

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
    my $bearer_token_scheme = $self->client->bearer_token_scheme;
    my @bearer_token_scheme = split ':', $bearer_token_scheme;
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
    
    if( $self->access_token and $self->expires_at > time() ){
        return $self->access_token;
    }

    # This is knitted specifically to Googles OAuth2 implementation - is it universal?
    my $headers = HTTP::Headers->new(
        Content_Type  => 'application/x-www-form-urlencoded',
        );
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
        croak( "No access token found in data...\n" );
    }
    foreach( qw/access_token token_type expires_in/ ){
        $self->{$_} = $obj->{$_} if $obj->{$_};
    }
    if( $obj->{expires_in} ){
        $self->{expires_at} = time + $obj->{expires_in};
    }
    return $self->{access_token};
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
    for (qw/access_token token_type refresh_token expires_in scope error error_desription error_uri state/) {
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
