#!/usr/bin/perl

use CGI;
use strict;
use warnings;

my $cgi = CGI->new;
my $name18 = $cgi->param('name');
my $name = substr($name18, 0, 16);

print qq(Content-type: text/plain\n\n);

my $filename = "/home/ubuntu/picoquic/cnx_log.txt";
open(my $fh, '<:encoding(UTF-8)', $filename)
  or die "Could not open file '$filename' $!";

my $line_count = 0;

while (my $row = <$fh>) {
  if ($row =~ /^$name/){
    $line_count += 1;
    chomp $row;
    print "$row\n";
  }
}

if ($line_count < 1){
  my $filename2 = "/home/ubuntu/picoquic/rcnx_log.txt";
  open(my $fh2, '<:encoding(UTF-8)', $filename2)
    or die "Could not open file '$filename2' $!";

  while (my $row2 = <$fh2>) {
    if ($row2 =~ /^$name/){
      $line_count += 1;
      chomp $row2;
      print "$row2\n";
    }
  }
}

if ($line_count < 1) {
  print "Sorry, cannot find log traces for $name\n";
}
