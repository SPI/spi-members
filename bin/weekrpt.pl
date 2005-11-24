#!/usr/bin/perl -w

use DBI;

my $DBNAME="spiapp";
my $DBUSER="spinm";

sub get_new_noncontrib_members($)
{
    my ($dbh) = @_;
    my ($firstname, $surname, $email, $apply_date);
    my $sth;
    my $sql = "SELECT m.name, m.email FROM applications a, members m WHERE m.ismember = 't' AND m.iscontrib = 'f' AND age('now'::date, a.validemail_date) < '1 week' AND m.memid = a.member ORDER BY a.approve_date, m.name";

    print "New Non-Contrib Members\n";
    print "=======================\n";
    print "\n";

    $sth = $dbh->prepare($sql);
    $sth->execute();
    $sth->bind_columns(\$name, \$email);
    while($sth->fetch()) {
        print "$name <$email>\n";
    }
    print "\n"
}


sub get_new_contrib_members($)
{
    my ($dbh) = @_;
    my ($firstname, $surname, $email, $apply_date);
    my $sth;
    my $sql = "SELECT m.name, m.email FROM applications a, members m WHERE m.iscontrib = 't' AND age('now'::date, a.approve_date) < '1 week' AND m.memid = a.member ORDER BY a.approve_date, m.name";

    print "New Contrib Members\n";
    print "===================\n";
    print "\n";

    $sth = $dbh->prepare($sql);
    $sth->execute();
    $sth->bind_columns(\$name, \$email);
    while($sth->fetch()) {
        print "$name <$email>\n";
    }
    print "\n"
}

my $dbh = DBI->connect("dbi:Pg:dbname=$DBNAME", $DBUSER, "");
get_new_noncontrib_members($dbh);
get_new_contrib_members($dbh);
$dbh->disconnect();

