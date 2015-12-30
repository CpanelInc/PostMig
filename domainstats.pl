#!/usr/local/cpanel/3rdparty/perl/514/bin/perl
use strict;
use warnings;
use DomainStatus;
use File::Slurp 'read_file';
use IPC::Open3;
use Term::ANSIColor qw(:constants);
$Term::ANSIColor::AUTORESET = 1;

#array of domains we're working with
our $fileName = "/etc/userdatadomains";
our @links    = read_file( $fileName );

#get the dns/http data 
sub get_data {
    #currently mean, but will nice it later(preserves term color)
    $SIG{'INT'} = sub { print "Caught CTRL+C!\n" };    
    #tell them what we're doing
    print "\n\t___Checking HTTP response codes and DNS A records___\n\n";
    #loop through domains found in @link /etc/userdatadomains file
    foreach my $uDomain ( @links ) {
        #if we look like the right snip, continue
        if ( $uDomain =~ /(.*):[\s]/ ) {
            our $resource = $1;
            #I had to wrap open3 in this, because I dont know
            eval {
                #sets some FH for out and err
                local ( *HIS_OUT, *HIS_ERR );
                #calls the routine for the $resource(domain)
                my $childpid =
                    open3( undef, *HIS_OUT, *HIS_ERR, \&DomainStatus::_get_http_status( "$resource" ), undef );
                #set the FH data array
                my @outlines = <HIS_OUT>;          
                my @errlines = <HIS_ERR>;          
                print "STDOUT:\n", @outlines, "\n";
                print "STDERR:\n", @errlines, "\n";
                #close handles
                close HIS_OUT;
                close HIS_ERR;
                #wait for kids
                waitpid( $childpid, 0 );
                #if we have a return code
                if ( $? ) {
                    print "Child exited with wait status of $?\n";
                }
            };
            #yep, second sub in eval here for open3
            eval {
                local ( *HIS_OUT2, *HIS_ERR2 );
                my $childpid2 =
                    open3( undef, *HIS_OUT2, *HIS_ERR2, \&DomainStatus::_get_dns_data( "$resource" ), undef );
                my @outlines2 = <HIS_OUT2>;
                my @errlines2 = <HIS_ERR2>;
                print "STDOUT:\n", @outlines2, "\n";
                print "STDERR:\n", @errlines2, "\n";
                close HIS_OUT2;
                close HIS_ERR2;
                waitpid( $childpid2, 0 );

                if ( $? ) {
                    print "Child exited with wait status of $?\n";
                }
            };
        } else {
            #if we didn't get a domain, lets tell them where we encountered munge
            print YELLOW "Possible bad Domain data enountered, manually check /etc/userdatadomains file.\n";
        }
    }
}

#run mail sub
sub shownMailAccounts {
    print "\n\n\t___Mail accounts found:___\n\n";
    &DomainStatus::_get_mail_accounts();
}

#this sub is to prevent stderr noise
sub supressERR($) {
    open my $saveout, ">&STDERR";
    open STDERR, '>', File::Spec->devnull();
    my $func = $_[0];
    $func->();
    open STDERR, ">&", $saveout;
}

#cAll the things
supressERR( \&get_data );
shownMailAccounts();
