use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Net::OAuth2',
    AUTHOR              => q{Robin Clarke <robin@robinclarke.net>},
    VERSION_FROM        => 'lib/Net/OAuth2.pm',
    ABSTRACT_FROM       => 'lib/Net/OAuth2.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More'			=> 0,
        'Data::Validate::URI'		=> 0,
        'URI'				=> 0,
        'Moose'				=> 0,
        'Moose::Util::TypeConstraints'	=> 0,
        'Test::NoWarnings'		=> 0,
        'Test::Mock::LWP::Dispatch'	=> 0,
        'YAML'				=> 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Net-OAuth2-*' },
);
