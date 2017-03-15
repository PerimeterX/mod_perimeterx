use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestRequest qw(GET);
use Apache::ModPerimeterXTestUtils;

plan tests => 1;

my $cookie = expired_cookie;

my $res = GET '/index.html', 'MyRealIP1' => '1.2.3.4', 'Cookie' => $cookie;

ok $res->code == 200
