#!/usr/local/cpanel/3rdparty/perl/514/bin/perl
use DomainStatus;
use File::Slurp 'read_file';
use File::Spec;
use strict;
use warnings;
use IPC::Open3;
our $fileName = "/etc/userdatadomains";
our @links    = read_file( $fileName );
$Term::ANSIColor::AUTORESET = 1;
use Term::ANSIColor qw(:constants);

sub get_data {
  $SIG{'INT'} = sub { print "\nCaught CTRL+C!..."; print RESET " ..Ending...\n" ; exit ; die ; kill HUP => -$$; }; 
    print "\n\t___Checking HTTP response codes and DNS A records___\n\n\t(be patient..)\n\n";
    foreach my $uDomain ( @links ) {
        if ( $uDomain =~ /(.*):[\s]/ ) {
            our $resource = $1;
            eval {
                local ( *HIS_OUT, *HIS_ERR );
                my $childpid =
                    open3( undef, *HIS_OUT, *HIS_ERR, \&DomainStatus::_get_http_status( "$resource" ), undef );
                my @outlines = <HIS_OUT>;          
                my @errlines = <HIS_ERR>;          
                print "STDOUT:\n", @outlines, "\n";
                print "STDERR:\n", @errlines, "\n";
                close HIS_OUT;
                close HIS_ERR;
                waitpid( $childpid, 0 );
                if ( $? ) {
                    print "Child exited with wait status of $?\n";
                }
            };
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
            print YELLOW "Possible bad Domain data enountered, manually check /etc/userdatadomains file after finished.\n";
        }
    }
}

sub showMailAccounts {
    print "\n\n\t___Mail accounts found:___\n\n";
    &DomainStatus::_get_mail_accounts();
}

sub supressERR($) {
    open my $saveout, ">&STDERR";
    open STDERR, '>', File::Spec->devnull();
    my $func = $_[0];
    $func->();
    open STDERR, ">&", $saveout;
}

&supressERR( \&get_data );
&showMailAccounts();
