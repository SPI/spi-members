#!/usr/bin/perl -w
# This script is run from spinm's crontab.
# 34 3,7,11,15,19,23 * * * /srv/members.spi-inc.org/bin/spi-private.pl

use DBI;

my $DBNAME = "spiapp";
my $DBUSER = "spinm";
my $file = "/srv/members.spi-inc.org/spi-private.txt";

my $dbh = DBI->connect("dbi:Pg:dbname=$DBNAME", $DBUSER, "");
if (! $dbh) {
    exit(1);
}
open(OUT, ">$file") || die "Cannot open '$file' for writing";
my ($name, $email);
my $sth;
# Get a listing of all members who have been approved as Contrib Members and
# who want to be subscribed to spi-private.
my $sql = "SELECT m.name, m.email FROM applications a, members m WHERE m.memid = a.member AND m.ismember = 't' AND m.iscontrib = 't' AND contribapp='t' AND sub_private = 't'";
$sth = $dbh->prepare($sql);
$sth->execute();
$sth->bind_columns(\$name, \$email);
while($sth->fetch()) {
    print OUT "$email\n";
}
$dbh->disconnect();
close(OUT);

