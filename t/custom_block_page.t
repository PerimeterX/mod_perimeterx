use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestUtil;
use Apache::TestRequest qw(GET POST);
use Data::Dump

my $url = '/index.html';

plan tests => 4;

# GET
my $get_res = GET $url, 'User-Agent' => 'PhantomJS';
ok $get_res->code == 403;
ok $post_res->content == "<html>
    <body>
        <h1>You are blocked!</h1>
    </body>
</html>"

# POST
my $post_res = POST $url, 'MyRealIP' => '1.2.3.4', 'User-Agent' => 'PahntomJS';
ok $post_res->code == 403;
ok $post_res->content == "<html>
    <body>
        <h1>You are blocked!</h1>
    </body>
</html>"
