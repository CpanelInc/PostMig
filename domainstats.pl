#!/usr/bin/perl
package DomainStatus;
use File::Spec;
use strict;
use warnings;
$Term::ANSIColor::AUTORESET = 1;
use Term::ANSIColor qw(:constants);
use threads;
use threads::shared;
use lib "/usr/local/cpanel/3rdparty/perl/514/lib64/perl5/cpanel_lib/";
use File::Slurp qw(read_file);
use Getopt::Long;

# setup my defaults
my $mail  = 0;
my $ipdns = 0;
my $all   = 0;
my $hosts = 0;
my $help  = 0;
my $jsons = 0;
our $fileName = "/etc/userdatadomains";
our @links    = read_file( $fileName );
our $linkRef  = \@links;
our $VERSION  = 0.02;

GetOptions( 'mail'  => \$mail,
            'ipdns' => \$ipdns,
            'all'   => \$all,
            'hosts' => \$hosts,
            'json'  => \$jsons,
            'help!' => \$help );

if ( $help ) {
    print "\n   Options:
     -help   -> This!
     -ipdns  -> Check http status, IP's, DNS IP's
     -hosts  -> Show suggested /etc/hosts file
     -mail   -> Check for email accounts
     -all    -> All the things!\n\n";
} elsif ( $mail ) {
    print "\n\n\tLets do some mail!\n\n";
    &_get_mail_accounts();
} elsif ( $ipdns ) {
    print "\n\n\tLets do some ipdns!\n";
    &supressERR( \&get_data );
} elsif ( $all ) {
    print "\n\tALL The Things!\n\n";
    &supressERR( \&get_data );
    &_gen_hosts_file();
    &_get_mail_accounts();
} elsif ( $hosts ) {
    print "\n\n\tThe hosts!!\n";
    &_gen_hosts_file();
} elsif ( $jsons ) {
    print "\njsons!\n\n";
    &_make_json_data();
} else {
    print "\n\thWhhut?! try -help ;p\n\n";
}

#this calls the subs with params in forks
sub get_data {
    $SIG{'INT'} = sub { print "\nCaught CTRL+C!.."; print RESET " Ending..\n"; exit; die; kill HUP => -$$; };
    print "\n\t::Checking HTTP response codes and DNS A records(be patient..)::\n\n";
    foreach my $uDomain ( @links ) {
        if ( $uDomain =~ /(.*):[\s]/ ) {
            our $resource = $1;
            my $thread1 = threads->create( \&_get_http_status, "$resource" );
            my $thread2 = threads->create( \&_get_dns_data,    "$resource" );
            $thread1->join();
            $thread2->join();
        } else {
            print YELLOW
                " Possible bad Domain data enountered, manually check /etc/userdatadomains file after finished.\n";
        }
    }
}

#this silences stderr
sub supressERR($) {
    open my $saveout, ">&STDERR";
    open STDERR, '>', File::Spec->devnull();
    my $func = $_[0];
    $func->();
    open STDERR, ">&", $saveout;
}

#this is a subroutine to check the http status code for domains
sub _get_http_status {
    $SIG{'INT'} = sub { print "\nCaught CTRL+C!.."; print RESET " Ending..\n"; exit; die; kill HUP => -$$; };

    #we use lwp/time/ansi for output/commands
    require LWP::UserAgent;
    require Time::HiRes;
    $Term::ANSIColor::AUTORESET = 1;
    use Term::ANSIColor qw(:constants);

    #our URL should come in as an argument to the subroutine
    my $url = "@_";

    #we have a basic browser agent and a low timeout for now, here's the request for the URL
    my $ua = LWP::UserAgent->new( agent => 'Mozilla/5.0', timeout => '1' );
    my $req = HTTP::Request->new( GET => "http://$url" );
    my $res = $ua->request( $req );

    #we can parse this for goodies/errors
    my $body = $res->decoded_content;

    #this is the status code
    my $code = $res->code();

    #we can easily check the headers to determine if we had a good request as below
    my $head = $res->headers()->as_string;
    print $res->header( "content-type\r\n\r\n" );

    #blue seems like a good color for requests that process(for now)
    my $bcode = ( BOLD BLUE $code );
    if ( $head =~ /Client-Peer:[\s](.*):([0-9].*)/ ) {
        my $head2 = "$1:$2";

        #here's some terrible formatting, needs improvement
        printf( " %-30s PeerIP=%-15s Status=%s\r\n", $url, $head2, $bcode );
    } else {

        #if we didn't see a normal header, let's print the code red with yellow warnings
        my $rcode = ( BOLD YELLOW $code );
        my $error = BOLD RED " ERROR:\t!!!HTTP Connect Failed : $url : $rcode!!!\n";
        print "$error";
    }
}

#this is a subroutine for DNS checks
sub _get_dns_data {
    $SIG{'INT'} = sub { print "\nCaught CTRL+C!.."; print RESET " Ending..\n"; exit; die; kill HUP => -$$; };

    #I found this here, it worked!
    use lib '/usr/local/cpanel/3rdparty/perl/514/lib64/perl5/cpanel_lib/';
    use IPC::System::Simple qw(system capture $EXITVAL);

    #colors again
    $Term::ANSIColor::AUTORESET = 1;
    use Term::ANSIColor qw(:constants);

    #here we can get the domain as a parameter and make some dig arguments
    my $domain     = "@_";
    my $cmd        = "dig";
    my @localArgs  = ( "\@localhost", "$domain", "A", "+short", "+tries=1" );
    my @googleArgs = ( "\@8.8.8.8", "$domain", "A", "+short", "+tries=1" );

    #so, this uses the lib found to capture stdout of the called system command
    #first we populate it into an array
    my @googleDNSA = capture( $cmd, @googleArgs );

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
        my $IPM1      = BOLD YELLOW " WARN: Local IP:";
        my $IPM2      = BOLD YELLOW " doesn't match remote DNS ";
        my $RlocalIP  = ( BOLD RED $localhostDNS );
        my $RgoogleIP = ( BOLD RED $googleDNS );
        chomp( $RlocalIP, $RgoogleIP );
        print "$IPM1" . "$RlocalIP" . "$IPM2" . "$RgoogleIP\n";
    } else {

        #if it's defined and matches, we do a normal thing:
        if ( ( $localhostDNS ) && ( "$localhostDNS" eq "$googleDNS" ) ) {
            print "$domain :: DNS IP: $googleDNS\n";
        } else {

            #else print yellow warning if nothing was returned
            print YELLOW "WARN: Something happened to DNS requests for $domain, is DNS set?\n";
        }
    }
}

sub _get_mail_accounts {
    print "\n\n\t::Mail accounts found::\n\n";
    use lib "/usr/local/cpanel/3rdparty/perl/514/lib64/perl5/cpanel_lib/";
    use File::Slurp qw(read_file);

    #read in users from passwd
    my @passwd = read_file( "/etc/passwd" );
    my $dir    = '/var/cpanel/users';
    my %user_list;
    opendir( DIR, $dir ) or die $!;
    while ( my $file = readdir( DIR ) ) {
        next if ( $file =~ m/^\./ );
        foreach my $line ( @passwd ) {

            #if we look like a system and cpanel user?
            if ( $line =~ /^$file:[^:]*:[^:]*:[^:]*:[^:]*:([a-z0-9_\/]+):.*/ ) {
                $user_list{$file} = $1;
            }
        }
    }
    closedir( DIR );

    #for the users found, if we aren't root look for an etc dir
    foreach my $user ( keys %user_list ) {
        if ( $user ne "root" ) {
            opendir( ETC, "$user_list{$user}/etc" ) || warn $! . "$user_list{$user}/etc";
            my $path = $user_list{$user};

            #for the domains found in the users etc dir
            while ( my $udomain = readdir( ETC ) ) {
                next if $udomain =~ /^\./;  # skip . and .. dirs
                                            #see if we are a valid etc domain and if so, look for mail users and print
                if ( -d "$path/etc/$udomain/" ) {
                    open( PASSWD, "$path/etc/$udomain/passwd" ) || die $! . "/home/$user/etc/$udomain/passwd";
                    while ( my $PWLINE = <PASSWD> ) {
                        $PWLINE =~ s/:.*//;    # only show line data before first colon (username only)
                        chomp( $user, $udomain, $PWLINE );
                        my $PWLINED = "$PWLINE\@$udomain";
                        chomp( $PWLINED );
                        printf( "User=%-10s Domain=%-35s Email=%s\n", $user, $udomain, $PWLINED );
                    }
                    close( PASSWD );
                }
            }
        }
        close( ETC );
    }
    print "\n";
}

sub _gen_hosts_file {
    print "\n\n\t::Hosts File::\n\n";
    foreach my $hostDomain ( @{$linkRef} ) {
        if ( $hostDomain =~ /==/ ) {
            $hostDomain =~ s/:[\s]/==/g;
            my ( $newDomain, $userName, $userGroup, $domainStatus, $primaryDomain, $homeDir, $IPport ) = split /==/,
                $hostDomain, 9;
            my ( $IP ) = split /:/, $IPport, 2;
            print "$IP\t\t$newDomain\twww.$newDomain\n";
        } else {
            next;
        }
    }
    print "\n";
}

sub _make_json_data {
    require LWP::UserAgent;
    $SIG{'INT'} = sub { print "\nCaught CTRL+C!.."; print RESET " Ending..\n"; exit; die; kill HUP => -$$; };
    my $head4;
    foreach my $jDomain ( @{$linkRef} ) {
        if ( $jDomain =~ /(.*):[\s]/ ) {
            my $url2 = $1;

            #we have a basic browser agent and a low timeout for now, here's the request for the URL
            my $ua = LWP::UserAgent->new( agent => 'Mozilla/5.0', timeout => '1' );
            my $req   = HTTP::Request->new( GET => "http://$url2" );
            my $reqIP = 0;
            my $res2  = $ua->request( $req );

            #we can parse this for goodies/errors
            my $body2 = $res2->decoded_content;

            #this is the status code
            my $code2 = $res2->code();

            #we can easily check the headers to determine if we had a good request as below
            my $head3 = $res2->headers()->as_string;
            print $res2->header( "content-type\r\n\r\n" );
            if ( $head3 =~ /Client-Peer:[\s](.*):([0-9].*)/ ) {
                $reqIP = "$1:$2";
            } else {

                #if we didn't see a normal header, let's print the code red with yellow warnings
                my $error2 = BOLD RED " ERROR:\t!!!HTTP Connect Failed : $url2 !!\n";
                print "$error2";
            }
            my ( $domain, $status ) = ( $url2, $code2 );

            sub new {

                my $class = shift;
                my $self = { Domain => shift,
                             IP     => shift,
                             Status => shift, };
                bless $self, $class;
                return $self;
            }

            sub TO_JSON { return { %{ shift() } }; }

            package main;
            use JSON;

            my $JSON = JSON->new->utf8;
            $JSON->convert_blessed( 1 );

            my $e = new DomainStatus( "$domain", "$reqIP", "$status" );
            my $json = $JSON->encode( $e );
            print "$json\n";
        }
    }
}
