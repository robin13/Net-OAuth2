use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Net::OAuth2',
    license             => 'perl',
    dist_author         => q{Keith Grennan <kgrennan@cpan.org>},
    dist_version_from   => 'lib/Net/OAuth2.pm',
    build_requires => {
        'Test::More' => 0,
        'Test::NoWarnings' => 0,
        'Test::Mock::LWP::Dispatch' => 0,
        'YAML' => 0,
    },
    requires => {
        'Class::Accessor' => '0.31',
        'LWP::UserAgent' => '0',
        'URI' => '0',
        'JSON' => '0',
    },    
    add_to_cleanup      => [ 'Net-OAuth2-*' ],
    create_makefile_pl => 'traditional',
);

$builder->create_build_script();
