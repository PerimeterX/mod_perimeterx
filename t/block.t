use strict;

use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestUtil;
use Apache::TestRequest qw(GET POST);

my $url = '/index.html';

plan tests => 2;

# GET
my $get_res = GET $url, 'User-Agent' => 'PhantomJS';
ok $get_res->code == 403;

# POST
my $post_res = POST $url, 'MyRealIP' => '1.2.3.4', 'User-Agent' => 'PahntomJS';
ok $post_res->code == 403;
