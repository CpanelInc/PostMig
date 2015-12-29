#!/usr/local/cpanel/3rdparty/perl/514/bin/perl
# cpanel				           Copyright(c) 2015 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited
#
#we dont really get parallel much yet, needs improvement to sync/sort
use Parallel::ForkManager;
use DomainStatus;
use File::Slurp 'read_file';
use strict;
use warnings;

# we read in the first "word"(domain) from the userdatadomains file
our $fileName = "/etc/userdatadomains";
our @links    = read_file( $fileName );

sub get_data {
#we make some parallel fork objects
    my $pm1 = new Parallel::ForkManager( 1 );
    my $pm2 = new Parallel::ForkManager( 4 );
    #loop through the domains, find if defined and begin
    foreach my $uDomain ( @links ) {
        #start forking with the pm object
        $pm1->start and next;
        if ( $uDomain =~ /(.*):[\s]/ ) {
            our $resource = $1;
        #if we're defined, let's fork off the second pm object
            $pm2->start and next;
            #hash of subs to do our work, can add more as we go
            my %subcalls = ( 'HTTPSTATUS' => \&DomainStatus::_get_http_status( "$resource" ),
                             'DDNSSTATUS' => \&DomainStatus::_get_dns_data( "$resource" ) );
            #references to the subs, I'd like to store the return and do something
            #for now they just exec
            my $httpref = &{ $subcalls{'HTTPSTATUS'} }();
            my $dnsref  = &{ $subcalls{'DDNSSTATUS'} }();
            #clean up after the kids
            $pm1->finish;
            $pm1->wait_all_children;
            $pm2->finish;
            $pm2->wait_all_children;
        } else {
            #if we didnt see a good domain in userdatadomains, we still
            #have to clean up after the kids, and tell what happened
            print "Bad Domain data.\n";
            $pm1->finish;
            $pm1->wait_all_children;
            $pm2->finish;
            $pm2->wait_all_children;
        }
        $pm1->finish;
        $pm1->wait_all_children;
    }
    $pm1->finish;
    $pm1->wait_all_children;

    $pm2->finish;
    $pm2->wait_all_children;
}


#this is a wrapper sub to disable stderr because I can't properly
#prevent the "Not a CODE reference error when calling my subroutines
#with a dynamic parameter((the domain)I *think* because the params anyway)
sub supressERR($) {
    open my $saveout, ">&STDERR";
    open STDERR, '>', File::Spec->devnull();
    my $func = $_[0];
    $func->();
    open STDERR, ">&", $saveout;
}

supressERR( \&get_data );
&DomainStatus::_get_mail_accounts();
