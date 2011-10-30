package Net::OAuth2::Moose::Client;
use Moose;

=head1 NAME

Net::OAuth2::Moose::Client - OAuth Client (version 2)

=head1 VERSION

0.01

=cut

our $VERSION = '0.01';

=head1 SEE ALSO

=head1 LICENSE AND COPYRIGHT

Copyright 2011 Robin Clarke

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=head1 CONTRIBUTORS

Thanks to Keith Grennan for Net::OAuth2 on which this is based

=cut

use Carp;
use LWP::UserAgent;
use URI;
use Net::OAuth2::Moose::AccessToken;
use MooseX::Types::URI qw(Uri FileUri DataUri);
use MooseX::Log::Log4perl;
use YAML;

has 'client_id'             => ( is => 'ro', isa => 'Str',                                           );
has 'client_secret'         => ( is => 'ro', isa => 'Str',                                           );
has 'scope'                 => ( is => 'ro', isa => Uri,     coerce => 1,                            );
has 'site_url_base'         => ( is => 'ro', isa => Uri,     coerce => 1,                            );
has 'access_token_url_base' => ( is => 'ro', isa => Uri,     coerce => 1,                            );
has 'access_token_path'     => ( is => 'ro', isa => 'Str',                                           );
has 'authorize_url_base'    => ( is => 'ro', isa => Uri,     coerce => 1,                            );
has 'authorize_path'	    => ( is => 'ro', isa => 'Str',                                           );
has 'refresh_token'         => ( is => 'ro', isa => 'Str',                                           );
has 'access_token'          => ( is => 'ro', isa => 'Str',                                           );
has 'access_code'           => ( is => 'ro', isa => 'Str',                                           );
has 'token_store'           => ( is => 'ro', isa => 'Str',                                           );
has 'access_token_method'   => ( is => 'ro', isa => 'Str',  required => 1, default => 'POST'         );
has 'bearer_token_scheme'   => ( is => 'ro', isa => 'Str',  required => 1, default => 'auth-header'  );
has 'profile'               => ( is => 'ro', isa => 'Str',  required => 1, default => 'application'  );
has 'keep_alive'            => ( is => 'ro', isa => 'Bool', required => 1, default => 2              );

has 'user_agent'            => ( 
    is          => 'ro', 
    isa         => 'LWP::UserAgent',
    writer      => '_set_user_agent',
    predicate   => '_has_user_agent',
    );

has 'access_token_object'   => ( is => 'rw',
    isa         => 'Net::OAuth2::AccessToken',
    builder     => '_build_access_token_object',
    lazy        => 1,
    );


around 'user_agent' => sub {
    my $orig = shift;
    my $self = shift;
    unless( $self->_has_user_agent ){
        $self->_set_user_agent( LWP::UserAgent->new( 'keep_alive' => $self->keep_alive ) );
    }
    return $self->$orig;
};



# Because a valid combination of parameters is not possible to define with 'has',
# doing a more complex param check before new
before 'new' => sub{
    my $class = shift;
    my %params = @_;
    
    my $found_valid = 0;
    my @valid = ( 
        [ qw/client_id client_secret site_url_base/ ],
        [ qw/access_token no_refresh_token_ok/ ],
        [ qw/refresh_token site_url_base/ ],
        );
    FOUND_VALID:
    foreach( @valid ){
        my @test = @{ $_ };
        if( scalar( grep{ $params{$_} } @test ) == scalar( @test ) ){
            $found_valid = 1;
            last FOUND_VALID;
        }
    }
    if( not $found_valid ){
        die( "Not initialised with a valid combination of parameters...\n" . Dump( \%params ) );
    }
};

sub _build_access_token_object {
    my $self = shift;
    my %req_params = @_;
    # Try to load an access token from the store first
    my $access_token = undef;
    my %token_params = ( client => $self );
    foreach( qw/client_id client_secret access_token refresh_token token_store user_agent/ ){
        $token_params{$_} = $self->$_ if $self->$_;
    }
    $access_token = Net::OAuth2::Moose::AccessToken->new( %token_params );
    $access_token->sync_with_store;
    if( not $access_token->refresh_token ){
        my $profile = $self->profile;        
        my $request;
        if ($self->access_token_method eq 'POST') {
            $request = POST($self->client->access_token_url(), {$self->access_token_params( %req_params)});
        } else {
            $request = HTTP::Request->new(
                $self->access_token_method => $self->access_token_url($self->access_token_params( %req_params))
            );
        }
        my $response = $self->user_agent->request($request);
        if( not $response->is_success ){
            croak( "Fetch of access token failed: " . $response->status_line . ": " . $response->decoded_content );
        }
        my $res_params = _parse_json($response->decoded_content);
        $res_params = _parse_query_string($response->decoded_content) unless defined $res_params;
        if( not defined $res_params ){
            croak( "Unable to parse access token response '".substr($response->decoded_content, 0, 64)."'" );
        }
        # TODO: RCL 2011-09-17 This is dirty... improve!
        $res_params->{token_store}  = $self->token_store if $self->token_store;
        $res_params->{user_agent}   = $self->user_agent;
        $access_token = Net::OAuth2::AccessToken->new(%$res_params);
        $access_token->sync_with_store;
    }
    return $access_token;
}

sub authorize_params {
    my $self = shift;
    my %options = @_;
    $options{scope}       ||= $self->scope;
    $options{client_id}   ||= $self->client_id;
    $options{response_type} ||= 'code';
    
    if( $self->profile eq 'webserver' ){
        # TODO: RCL 2011-10-04 redirect_uri must be defined if profile eq 'webserver'
        $options{redirect_uri}  ||= $self->redirect_uri;
        # legacy for pre v2.09 (37Signals)
        $options{type}          =   'web_server';
    } else {
        $options{redirect_uri}  = 'urn:ietf:wg:oauth:2.0:oob';
    }
    return %options;
}

sub access_token_params {
    my $self = shift;
    my %options = @_;  
    $options{client_id}         ||= $self->client_id;
    $options{client_secret}     ||= $self->client_secret;
    $options{grant_type}        ||= $self->grant_type;
    if( $self->profile eq 'webserver' ){
        $options{redirect_uri}  ||= $self->redirect_uri;
        # legacy for pre v2.09 (37Signals)
        $options{type}          = 'web_server';
    } else {
        $options{redirect_uri}  = 'urn:ietf:wg:oauth:2.0:oob';
    }
    return %options;
}

sub refresh_access_token {
    my $self = shift;

    # Make it expire now
    $self->access_token_object->expires_at( time() );

    # Request a fresh access token
    $self->access_token_object->valid_access_token();
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
    return $self->user_agent->request( $request );
}


sub authorize_url {
    return shift->_make_url("authorize", @_);
}

sub access_token_url {
    return shift->_make_url("access_token", @_);
}

sub site_url {
    my $self = shift;
    my $path = shift;
    my %params = @_;
    my $url;
    if( $self->site_url_base ) {
        $url = URI->new_abs($path, $self->site_url_base );
    }
    else {
        $url = URI->new($path);
    }
    if (@_) {
        $url->query_form($url->query_form , %params);
    }
    return $url;
}

sub _make_url {
    my $self = shift;
    my $thing = shift;
    my $path = $self->{"${thing}_url_base"} || $self->{"${thing}_path"} || "/oauth/${thing}";
    return $self->site_url($path, @_);
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



1;
