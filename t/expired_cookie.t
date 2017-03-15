use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestRequest qw(GET);
use Apache::ModPerimeterXTestUtils;

plan tests => 1;

my $cookie = expired_cookie;

my $res = GET '/index.html', 'real-ip' => '1.2.3.4', 'Cookie' => $cookie;

my $key = 'x-px-call-reason';
my $call_reason = $res->headers->{$key};
ok $res->code == 200
ok $call_reason eq 'cookie_expired';

