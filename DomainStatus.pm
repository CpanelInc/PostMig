#!/usr/local/cpanel/3rdparty/perl/514/bin/perl
package DomainStatus;
use strict;
use warnings;
use File::Slurp qw(read_file);
our $VERSION = 0.02;

sub _get_http_status {
    require LWP::UserAgent;
    require Time::HiRes;
    $Term::ANSIColor::AUTORESET = 1;
    use Term::ANSIColor qw(:constants);
    my $url        = "@_";
    my $ua         = LWP::UserAgent->new( agent => 'Mozilla/5.0', timeout => '1' );
    my $req        = HTTP::Request->new( GET => "http://$url" );
    my $start      = [ Time::HiRes::gettimeofday() ];
    my $res        = $ua->request( $req );
    my $difference = Time::HiRes::tv_interval( $start );
    my $body       = $res->decoded_content;
    my $code       = $res->code();
    my $head       = $res->headers()->as_string;
    print $res->header( "content-type\r\n\r\n" );
    my $bcode = ( BOLD BLUE $code );

    if ( $head =~ /Client-Peer:[\s](.*):([0-9].*)/ ) {
        my $head2 = "$1:$2";
        printf( "%-35s IP=%-22s Status=%s Time=%-5ss\r\n", $url, $head2, $bcode, $difference );
    } else {
        my $rcode = ( RED $code );
        my $error = BOLD YELLOW "ERROR:\t!!!Connect Failed : $url : $rcode!!!";
        print "$error\n";
    }
}

sub _get_dns_data {
    use lib '/usr/local/cpanel/3rdparty/perl/514/lib64/perl5/cpanel_lib/';
    use IPC::System::Simple qw(system capture $EXITVAL);
    $Term::ANSIColor::AUTORESET = 1;
    use Term::ANSIColor qw(:constants);

    my $domain     = "@_";
    my $cmd        = "dig";
    my @localArgs  = ( "\@localhost", "$domain", "A", "+short", "+tries=1" );
    my @googleArgs = ( "\@localhost", "$domain", "A", "+short", "+tries=1" );

    my @googleDNSA    = capture( $cmd, @googleArgs );
    my $googleDNSR    = \@googleDNSA;
    my $googleDNS     = $googleDNSR->[0];
    my @localhostDNSA = capture( $cmd, @localArgs );
    my $localhostDNSR = \@localhostDNSA;
    my $localhostDNS  = $localhostDNSR->[0];
    chomp( $googleDNS, $localhostDNS );

    if ( ( $localhostDNS ) && ( $localhostDNS ne $googleDNS ) ) {
        my $IPM1      = BOLD YELLOW "WARN: Local IP:";
        my $IPM2      = BOLD YELLOW " doesn't match remote DNS ";
        my $RlocalIP  = ( BOLD RED $localhostDNS );
        my $RgoogleIP = ( BOLD RED $googleDNS );
        print "$IPM1" . "$RlocalIP" . "$IPM2" . "$RgoogleIP\n";
    } else {
        if ( ( $localhostDNS ) && ( "$localhostDNS" eq "$googleDNS" ) ) {
            print "DNS IP: $googleDNS : $domain\n";
        } else {
            print YELLOW "WARN: Something bad happened with our DNS request for $domain, DNS possibly not set.\n";
        }
    }
}

sub _get_mail_accounts {
    my @passwd = read_file( "/etc/passwd" );
    my $dir    = '/var/cpanel/users';
    my %user_list;

    opendir( DIR, $dir ) or die $!;
    while ( my $file = readdir( DIR ) ) {
        next if ( $file =~ m/^\./ );
        foreach my $line ( @passwd ) {
            if ( $line =~ /^$file:[^:]*:[^:]*:[^:]*:[^:]*:([a-z0-9_\/]+):.*/ ) {
                $user_list{$file} = $1;
            }
        }
    }
    closedir( DIR );

    foreach my $user ( keys %user_list ) {
        if ( $user ne "root" ) {
            opendir( ETC, "$user_list{$user}/etc" ) || warn $! . "$user_list{$user}/etc";
            my $path = $user_list{$user};
            while ( my $domain = readdir( ETC ) ) {
                next if $domain =~ /^\./;    # skip . and .. dirs
                if ( -d "$path/etc/$domain/" ) {
                    open( PASSWD, "$path/etc/$domain/passwd" ) || die $! . "/home/$user/etc/$domain/passwd";
                    while ( my $PWLINE = <PASSWD> ) {
                        $PWLINE =~ s/:.*//;    # only show line data before first colon (username only)
                        chomp( $user, $domain, $PWLINE );
                        my $PWLINED = "$PWLINE\@$domain";
                        chomp( $PWLINED );

                        #                print "User:$user Domain:$domain Email:" . $PWLINE . "";
                        printf( "User=%-10s Domain=%-35s Email=%s\n", $user, $domain, $PWLINED );
                    }
                    close( PASSWD );
                }
            }
        }
        close( ETC );
    }
}

1
