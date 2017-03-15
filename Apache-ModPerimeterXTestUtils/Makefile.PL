use 5.022001;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Apache::ModPerimeterXTestUtils',
    VERSION_FROM      => 'lib/Apache/ModPerimeterXTestUtils.pm', # finds $VERSION, requires EU::MM from perl >= 5.5
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ABSTRACT_FROM     => 'lib/Apache/ModPerimeterXTestUtils.pm', # retrieve abstract from module
    AUTHOR            => 'Aviad Shikloshi <aviad@perimeterx.com>',
);
