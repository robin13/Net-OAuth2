package Net::OAuth2::Client;
use warnings;
use strict;
use Carp;
use base qw(Class::Accessor::Fast);
__PACKAGE__->mk_accessors(qw/id secret user_agent site scope bearer_token_scheme access_code/);
use LWP::UserAgent;
use URI;
use Net::OAuth2::Profile::WebServer;
use Net::OAuth2::Profile::Application;

sub new {
    my $class = shift;
    my $client_id = shift;
    my $client_secret = shift;
    my %opts = @_;
    $opts{id}                   =   $client_id;
    $opts{secret}               =   $client_secret;
    $opts{user_agent}           ||= LWP::UserAgent->new;
    $opts{bearer_token_scheme}  ||= 'auth-header';
    
    my $self = bless \%opts, $class;
    return $self;
}

sub access_token {
    my $self = shift;
    if( $self->{access_token} ){
        return $self->{access_token};
    }

    # Refresh token is the most important
    if( $self->{refresh_token} ){
        $self->{access_token} = Net::OAuth2::AccessToken->new( 
            refresh_token   => $self->{refresh_token},
            client          => $self,
            );
        return $self->{access_token};
    }

    my $profile = $self->{profile} || 'application';
    
    if( $profile eq 'application' and not $self->access_code ){
        croak( "Please authorize your application with this URL, and start again with the parameter access_code\n" .
            $self->$profile->authorize_uri() );
    }

    $self->{access_token} = $self->$profile->get_access_token;
    return $self->{access_token};
}

sub application {
    my $self = shift;
    return Net::OAuth2::Profile::Application->new(client => $self, @_);
}

sub web_server {
    my $self = shift;
    return Net::OAuth2::Profile::WebServer->new(client => $self, @_);
}

sub request {
    my $self = shift;
    my $response = $self->user_agent->request(@_);
}

sub authorize_url {
    return shift->_make_url("authorize", @_);
}

sub access_token_url {
    return shift->_make_url("access_token", @_);
}

sub access_token_method {
    return shift->{access_token_method} || 'POST';
}

sub _make_url {
    my $self = shift;
    my $thing = shift;
    my $path = $self->{"${thing}_url"} || $self->{"${thing}_path"} || "/oauth/${thing}";
    return $self->site_url($path, @_);
}

sub site_url {
    my $self = shift;
    my $path = shift;
    my %params = @_;
    my $url;
    if (defined $self->{site}) {
        $url = URI->new_abs($path, $self->{site});
    }
    else {
        $url = URI->new($path);
    }
    if (@_) {
        $url->query_form($url->query_form , %params);
    }
    return $url;
}

=head1 NAME

Net::OAuth2::Client - OAuth Client

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
