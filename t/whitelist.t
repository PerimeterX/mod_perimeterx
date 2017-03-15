use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestRequest qw(GET);
use Apache::ModPerimeterXTestUtils;

plan tests => 2;

my $cookie = valid_bad_cookie;

# whitelist per user agent
my $route_wl_res = GET '/server-status', 'real-ip' => '1.2.3.4', 'Cookie' => $cookie;
ok $route_wl_res->code == 200

# whitelist per route
# TODO: find a way to change the request useragent
#my $ua_wl_res = GET '/index.html', 'Cookie' => $cookie, 'User-Agent' => 'whitelisted-useragent';
#ok $ua_wl_res->code = 200;
