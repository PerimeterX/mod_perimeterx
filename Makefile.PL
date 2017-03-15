require 5.6.1;

use ExtUtils::MakeMaker;

use Apache::TestMM qw(test clean); #enable 'make test'

use lib qw(../blib/lib lib);

my %require => {
    "Apache::Test" => "",
};

my @scripts = qw(t/TEST);

Apache::TestMM::filter_args();
Apache::TestMM::generate_script('t/TEST');

WriteMakefile(
    #NAME => 'Apache::Test_mod_perimeterx',
    #NAME => 'Apache::TestModPerimeterX',
    #VERSION_FROM => 'lib/Apache/ModPerimeterX.pm',
    VERSION => '0.0.1',
    PREREQ_PM => \%require,
    clean => {
        FILES => "@{ clean_files() }",
    },
    ($] >= 5.005 ?
        (
            ABSTRACT => 'Testing mod_perimeterx',
            #ABSTRACT_FROM => 'lib/Test/ModPerimeterX.pm',
            AUTHOR => 'Aviad Shikloshi <aviad (at) perimeterx.com>',
        ) : ()
    ),
);

sub clean_files {
    return [@scripts];
}

