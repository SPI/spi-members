#!/usr/bin/perl -w
# This script is run daily from spinm's crontab.
# 1 4 * * * /srv/members.spi-inc.org/bin/inform-new-apps.pl

use DBI;

my $DBNAME = "spiapp";
my $DBUSER = "spinm";

my $dbh = DBI->connect("dbi:Pg:dbname=$DBNAME", $DBUSER, "");
if (! $dbh) {
    exit(1);
}
my ($name, $email, $appdate);
my $sth;
# Get a listing of all contrib applications which have been filed
# yesterday
my $sql = "SELECT m.name, m.email, a.appdate FROM applications a, members m WHERE m.memid = a.member AND m.ismember = 't' AND a.approve IS NULL AND contribapp= 't' AND CURRENT_TIMESTAMP - a.appdate < '2 days'";
$sth = $dbh->prepare($sql);
$sth->execute();
$sth->bind_columns(\$name, \$email, \$appdate);
my $number = $sth->rows;
if ($number > 0) {
    open (FP, "| /usr/lib/sendmail -t") or die "Cannot open to sendmail $!";
    print FP "To: membership\@spi-inc.org\n";
    print FP "From: SPI Membership Committee <membership\@spi-inc.org>\r\n";
    print FP "Errors-To: membership\@spi-inc.org\r\n";
    print FP "Subject: New SPI Contrib applications: $number\n";
    print FP "\n";
    print FP "The following " . $number . " applications are new:\n";
    print FP "\n";
    while($sth->fetch()) {
        print FP "$appdate: $name <$email>\n";
    }
    close(FP);
}
$sth->finish();
$dbh->disconnect();

