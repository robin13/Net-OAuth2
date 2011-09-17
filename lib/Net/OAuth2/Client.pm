package Net::OAuth2::Client;
use Moose;

=head1 NAME

Net::OAuth2::Client - OAuth Client

=head1 VERSION

0.09

=cut

our $VERSION = '0.09';

=head1 SEE ALSO

L<Net::OAuth>

=head1 CONTRIBUTORS

Robin Clarke

=head1 LICENSE AND COPYRIGHT

Copyright 2010 Keith Grennan.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

use Carp;
use LWP::UserAgent;
use URI;
use Net::OAuth2::Profile::WebServer;
use Net::OAuth2::Profile::Application;
use MooseX::Types::URI qw(Uri FileUri DataUri);

has 'id'                    => ( is => 'ro', isa => 'Str',                                           );
has 'secret'                => ( is => 'ro', isa => 'Str',                                           );
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
has 'keep_alive'            => ( is => 'ro', isa => 'Bool', required => 1, default => 0              );

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

has 'webserver' => ( 
    is		=> 'ro', 
    isa         => 'Net::OAuth2::Profile::WebServer',
    writer	=> '_set_webserver',
    predicate	=> '_has_webserver',
    );

has 'application' => ( 
    is		=> 'ro', 
    isa         => 'Net::OAuth2::Profile::Application',
    writer	=> '_set_application',
    predicate	=> '_has_application',
    );

around 'user_agent' => sub {
    my $orig = shift;
    my $self = shift;
    unless( $self->_has_user_agent ){
        $self->_set_user_agent( LWP::UserAgent->new( 'keep_alive' => $self->keep_alive ) );
    }
    return $self->$orig;
};


around 'webserver' => sub {
    my $orig = shift;
    my $self = shift;
    unless ($self->_has_webserver) {
	$self->_set_webserver( Net::OAuth2::Profile::WebServer->new( client => $self, @_ ) );
    }
    return $self->$orig;
};

around 'application' => sub {
    my $orig = shift;
    my $self = shift;
    unless ($self->_has_application) {
	$self->_set_application( Net::OAuth2::Profile::Application->new( client => $self, @_ ) );
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
        [ qw/id secret site_url_base/ ],
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
        use YAML;
#        die( Dump( \%params ) );
        die( "Not initialised with a valid combination of parameters...\n" . Dump( \%params ) );
    }
};



sub request {
    my $self = shift;
    my $response = $self->user_agent->request(@_);
}

# Wrappers around the token objects http methods
sub get {
    my $self = shift;
    my $response = $self->access_token_object->get(@_);
}

sub post {
    my $self = shift;
    my $response = $self->access_token_object->post(@_);
}

sub put {
    my $self = shift;
    my $response = $self->access_token_object->put(@_);
}

sub delete {
    my $self = shift;
    my $response = $self->access_token_object->delete(@_);
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

sub _build_access_token_object {
    my $self = shift;

    # Try to load an access token from the store first
    my $access_token = undef;
    my %token_params = ( client => $self );
    foreach( qw/access_token refresh_token token_store/ ){
        $token_params{$_} = $self->$_ if $self->$_;
    }
    $access_token = Net::OAuth2::AccessToken->new( %token_params );
    $access_token->sync_with_store;

    if( not $access_token->refresh_token ){
        my $profile = $self->profile;
        $access_token = $self->$profile->get_access_token( $self->access_code );
        $access_token->sync_with_store();
    }
    return $access_token;
}

1;
