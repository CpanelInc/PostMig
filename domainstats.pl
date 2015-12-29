#!/usr/local/cpanel/3rdparty/perl/514/bin/perl
use Parallel::ForkManager;
use DomainStatus;
use File::Slurp 'read_file';
use strict;
use warnings;

our $fileName = "/etc/userdatadomains";
our @links    = read_file( $fileName );
our @arrayholder;

sub get_data {
    my $pm1 = new Parallel::ForkManager( 1 );
    my $pm2 = new Parallel::ForkManager( 4 );
    foreach my $uDomain ( @links ) {
        $pm1->start and next;
        if ( $uDomain =~ /(.*):[\s]/ ) {
            our $resource = $1;
            $pm2->start and next;
            my %subcalls = ( 'HTTPSTATUS' => \&DomainStatus::_get_http_status( "$resource" ),
                             'DDNSSTATUS' => \&DomainStatus::_get_dns_data( "$resource" ) );
            my $httpref = &{ $subcalls{'HTTPSTATUS'} }();
            my $dnsref  = &{ $subcalls{'DDNSSTATUS'} }();
            $pm1->finish;
            $pm1->wait_all_children;
            $pm2->finish;
            $pm2->wait_all_children;
        } else {
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

sub supressERR($) {
    open my $saveout, ">&STDERR";
    open STDERR, '>', File::Spec->devnull();
    my $func = $_[0];
    $func->();
    open STDERR, ">&", $saveout;
}

supressERR( \&get_data );
