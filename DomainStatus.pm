#!/usr/local/cpanel/3rdparty/perl/514/bin/perl
# cpanel				           Copyright(c) 2015 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

package DomainStatus;
use strict;
use warnings;
our $VERSION = 0.02;

#this is a subroutine to check the http status code for domains
sub _get_http_status {
    #we use lwp/time/ansi for output/commands
    require LWP::UserAgent;
    require Time::HiRes;
    $Term::ANSIColor::AUTORESET = 1;
    use Term::ANSIColor qw(:constants);
    #our URL should come in as an argument to the subroutine
    my $url        = "@_";
    #we have a basic browser agent and a low timeout for now, here's the request for the URL
    my $ua         = LWP::UserAgent->new( agent => 'Mozilla/5.0', timeout => '1' );
    my $req        = HTTP::Request->new( GET => "http://$url" );
    #here is a time starter for the request to get a difference
    my $start      = [ Time::HiRes::gettimeofday() ];
    my $res        = $ua->request( $req );
    #this *should* be about how long the request took as an http client
    my $difference = Time::HiRes::tv_interval( $start );
    #we can parse this for goodies/errors
    my $body       = $res->decoded_content;
    #this is the status code
    my $code       = $res->code();
    #we can easily check the headers to determine if we had a good request as below
    my $head       = $res->headers()->as_string;
    print $res->header( "content-type\r\n\r\n" );
    #blue seems like a good color for requests that process(for now)
    my $bcode = ( BOLD BLUE $code );
    if ( $head =~ /Client-Peer:[\s](.*):([0-9].*)/ ) {
        my $head2 = "$1:$2";
        #here's some terrible formatting, needs improvement
        printf( "%-35s IP=%-22s Status=%s Time=%-5ss\r\n", $url, $head2, $bcode, $difference );
    } else {
        #if we didn't see a normal header, let's print the code red with yellow warnings
        my $rcode = ( RED $code );
        my $error = BOLD YELLOW "ERROR:\t!!!Connect Failed : $url : $rcode!!!";
        print "$error\n";
    }
}

#this is a subroutine for DNS checks
sub _get_dns_data {
    #I found this here, it worked!
    use lib '/usr/local/cpanel/3rdparty/perl/514/lib64/perl5/cpanel_lib/';
    use IPC::System::Simple qw(system capture $EXITVAL);
    #colors again
    $Term::ANSIColor::AUTORESET = 1;
    use Term::ANSIColor qw(:constants);
    #here we get the domain as a parameter and make some dig arguments
    my $domain     = "@_";
    my $cmd        = "dig";
    my @localArgs  = ( "\@localhost", "$domain", "A", "+short", "+tries=1" );
    my @googleArgs = ( "\@8.8.8.8", "$domain", "A", "+short", "+tries=1" );
    #so, this uses the IPC system lib above to capture stdout of the called system command
    #first we populate it into an array
    my @googleDNSA    = capture( $cmd, @googleArgs );
    #then we reference out the first element because we want a singular return
    #then we do the same for localhost requests
    my $googleDNSR    = \@googleDNSA;
    my $googleDNS     = $googleDNSR->[0];
    my @localhostDNSA = capture( $cmd, @localArgs );
    my $localhostDNSR = \@localhostDNSA;
    my $localhostDNS  = $localhostDNSR->[0];
    chomp( $googleDNS, $localhostDNS );

    #if the request is defined but doesn't match:
    if ( ( $localhostDNS ) && ( $localhostDNS ne $googleDNS ) ) {
        my $IPM1      = BOLD YELLOW "WARN: Local IP:";
        my $IPM2      = BOLD YELLOW " doesn't match remote DNS ";
        my $RlocalIP  = ( BOLD RED $localhostDNS );
        my $RgoogleIP = ( BOLD RED $googleDNS );
        print "$IPM1" . "$RlocalIP" . "$IPM2" . "$RgoogleIP\n";
    } else {
        #if it's defined and matches, we do a normal thing:
        if ( ( $localhostDNS ) && ( "$localhostDNS" eq "$googleDNS" ) ) {
            print "DNS IP: $googleDNS : $domain\n";
        } else {
            #else print yellow warning if nothing was returned
            print YELLOW "WARN: Something bad happened with our DNS request for $domain, DNS possibly not set.\n";
        }
    }
}
1
