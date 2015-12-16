#!/usr/local/cpanel/3rdparty/perl/514/bin/perl
use LWP::UserAgent;
use Time::HiRes;
use Parallel::ForkManager;

package DomainStatus;
our $VERSION = 0.01;

sub getStatus {
    use File::Slurp 'read_file';
    my $pm = new Parallel::ForkManager(10);
    our $fileName = "/etc/userdatadomains";
    our @links    = read_file($fileName);
    foreach my $uDomain (@links) {
        if ( $uDomain =~ /(.*):[\s]/ ) {
            my $url = $1;
            $pm->start and next;    # do the fork
            my $ua = LWP::UserAgent->new( agent => 'Mozilla/5.0' );
            my $req        = HTTP::Request->new( GET => "http://$url" );
            my $start      = [ Time::HiRes::gettimeofday() ];
            my $res        = $ua->request($req);
            my $difference = Time::HiRes::tv_interval($start);
            my $body       = $res->decoded_content;
            my $code       = $res->code();
            my $head       = $res->headers()->as_string;
            print $res->header("content-type\r\n\r\n");

            if ( $head =~ /Client-Peer:[\s](.*):([0-9].*)/ ) {
                my $head2 = "$1:$2";
                printf( "%-40s IP:PORT=%-22s Status=%s ReqTime=%-5ss\r\n",
                    $url, $head2, $code, $difference );
            }
            else {
                printf("%s %-10s Couldn't Connect! $url, $code\n");
                $pm->finish;
                $pm->wait_all_children;
            }
            $pm->finish;
            $pm->wait_all_children;
        }
    }
    $pm->finish;
    $pm->wait_all_children;
}
1
