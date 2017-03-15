package Apache::ModPerimeterXTestUtils;

use 5.022001;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Apache::ModPerimeterXTestUtils ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(

) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

#bake_cookie
our @EXPORT = qw(
    valid_good_cookie
    valid_bad_cookie
    expired_cookie
);

sub bake_cookie {
    use Crypt::KeyDerivation 'pbkdf2';
    use Crypt::Misc 'encode_b64', 'decode_b64';
    use Crypt::Mac::HMAC 'hmac_hex';
    use Crypt::Mode::CBC;

    my ( $ip, $ua, $score, $uuid, $vid, $time ) = @_;
    my $data = $time . '0' . $score . $uuid . $vid . $ua;

    my $password        = 'perimeterx';
    my $salt            = '12345678123456781234567812345678';
    my $iteration_count = 1000;
    my $hash_name       = undef;                              #default is SHA256
    my $len             = 48;

    my $km = pbkdf2( $password, $salt, $iteration_count, $hash_name, $len );
    my $key = substr( $km, 0,  32 );
    my $iv  = substr( $km, 32, 48 );

    my $m         = Crypt::Mode::CBC->new('AES');
    my $hmac      = hmac_hex( 'SHA256', $password, $data );
    my $plaintext = '{"t":'
      . $time
      . ', "s":{"b":'
      . $score
      . ', "a":0}, "u":"'
      . $uuid
      . '", "v":"'
      . $vid
      . '", "h":"'
      . $hmac . '"}';
    my $ciphertext = $m->encrypt( $plaintext, $key, $iv );

    my $cookie = encode_b64($salt) . ":" . 1000 . ":" . encode_b64($ciphertext);
    return '_px=' . $cookie;
}

sub valid_good_cookie {
    my $time = ( time() + 360 ) * 1000;
    return bake_cookie(
        "1.2.3.4",
        "libwww-perl/0.00",
        "20",
        "57ecdc10-0e97-11e6-80b6-095df820282c",
        "vid",
        $time
    );
}

sub valid_bad_cookie {
    my $time = ( time() + 360 ) * 1000;
    return bake_cookie(
        "1.2.3.4",
        "libwww-perl/0.00",
        "100",
        "57ecdc10-0e97-11e6-80b6-095df820282c",
        "vid",
        $time
    );
}

sub expired_cookie {
    my $expierd_time = ( time() - 24*60*60);
    return bake_cookie(
        "1.2.3.4",
        "libwww-perl/0.00",
        "20",
        "57ecdc10-0e97-11e6-80b6-095df820282c",
        "vid",
        $expierd_time
    );
}


our $VERSION = '0.01';


# Preloaded methods go here.

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Apache::ModPerimeterXTestUtils - Perl extension for mod_perimeterx Test utils

=head1 SYNOPSIS

  use Apache::ModPerimeterXTestUtils;

=head1 DESCRIPTION

Stub documentation for Apache::ModPerimeterXTestUtils, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

bake_cookie


=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Aviad Shikloshi, E<lt>aviad@perimeterx.com<gt>

=cut
