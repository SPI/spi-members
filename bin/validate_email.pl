#!/usr/bin/perl
#
# This validates an incoming email (from stdin) to make sure the email
# address works
#
use DBI;

my $DBNAME="spiapp";
my $DBUSER="spinm";
# not needed since non-contrib memberships don't expire
#my $MEMBERSHIP_LENGTH='1 year';

my $spierr = "";
my $applicant_name = "applicant";
my $applicant_email = "nobody\@nohost";

sub send_email(@)
{
    my ($email, $body, $subject) = @_;

    open (FP, "| /usr/lib/sendmail -t") or die "Cannot open to sendmail $!";
    print FP "To: $email\n";
    print FP "From: SPI New-Member <membership\@spi-inc.org>\n";
    print FP "Errors-To: SPI Members Admins <admin\@members.spi-inc.org>\n";

    print FP "Subject: $subject\n\n";
    print FP $body;
    close FP;
}

sub send_goodemail(@)
{
  my ($email) = @_;
  my ($dbh, $sth, $sql);
  my $expirydate = 'unknown';

  $body = "Congratulations!\n\n";
  $body .= "  The verification of your email address has succeeded and you are now\n";
  $body .= "a non-contributing member of SPI.  Non-contributing memberships do not\n";
  $body .= "expire.\n\n";
  $body .= "Application Information:\nName: ".$main::applicant_name."\n";
  $body .= "Email: " . $main::applicant_email . "\n\n";
  $body .= "  If you wish to obtain a contributing membership but have not yet\n";
  $body .= "applied for it, please log in at <https://members.spi-inc.org/> and fill\n";
  $body .= "out the application information.  You can check the status of your\n";
  $body .= "application or update your personal information on this web page at any\n";
  $body .= "time.\n\n";
  $body .= "Welcome to SPI!\n\n";
  $body .= "Software in the Public Interest, Inc.\n";

  send_email($main::applicant_email, $body, "Non-contributing SPI membership application successful");
}

sub send_bademail(@)
{
  my ($email) = @_;

  $body = "Your verification for your email address failed for some reason.\n";
  $body .= "Below may be some extra information for you:\n\n";
  $body .= $main::spierr;
  send_email($email, $body, "SPI Email Check Failed");
}
sub verify_email(@)
{
  my ($email, $randkey) = @_;
  my ($dbh, $sth, $sql);
  my $debug = $main::debug;

  print "Verifying email from $email with key $randkey\n" if $debug;

  # Connect to database
  if (! ($dbh = DBI->connect("dbi:Pg:dbname=$DBNAME", $DBUSER, ""))) {
    $main::spierr .= "Could not connect to database.\n";
    return 0;
  }

  # Find member and application that used this email key
  $sql = "SELECT member, appid, validemail from applications WHERE emailkey ='$randkey'";
  if (! (@approw = $dbh->selectrow_array($sql))) {
    $main::spierr .= "Problem finding application with key '$randkey' in database.\n";
    $dbh->disconnect;
    return 0;
  }
  $memid = $approw[0];
  $appid = $approw[1];
  $validemail = $approw[2];
  print "Application ID: $appid, Member ID: $memid\n" if $debug;
  if ($validemail) {
      $main::spierr .= "You have already confirmed your membership.\n";
      $dbh->disconnect;
      return 0;
  }

  # Update application
  $sql = "UPDATE applications SET validemail = 't', validemail_date = 'now'::date WHERE appid='$appid' AND ";
  $sql .= "( validemail = 'f' OR validemail IS NULL) ";
  print "SQL is: $sql\n" if $debug;
  if ($dbh->do($sql) != 1) {
    print "Key not found in database\n" if $debug;
    $main::spierr .= "Validation key $randkey found in application database but application $appid was not.\n";
    $dbh->disconnect;
    return 0; }

  print "Key was found in database\n" if $debug;

  # Set the ismember flag
  $sql = "UPDATE members SET ismember = 't' WHERE memid = '$memid'";
  print "SQL is: $sql\n" if $debug;
  if ($dbh->do($sql) != 1) {
    $main::spierr .= "Could not update member status after finding valid key.\nSQL was: $sql\n";
    $dbh->disconnect;
    return 0;
  }
  # set inital date
  $sql = "UPDATE members SET firstdate = 'today'::date WHERE memid = '$memid' AND firstdate IS NULL";
  if ($dbh->do($sql) != 1) {
    $main::spierr .= "Could not update member status after finding valid key.\nSQL was: $sql\n";
    $dbh->disconnect;
    return 0;
  }

# not needed since non-contrib memberships don't expire
#  $sql = "UPDATE members SET expirydate = 'today'::date + '$MEMBERSHIP_LENGTH'::interval WHERE memid = '$memid'";
#  if ($dbh->do($sql) != 1) {
#    $main::spierr .= "Could not update member status after finding valid key.\nSQL was: $sql\n";
#    $dbh->disconnect;
#    return 0;
#  }

  # Get the members name
  $sql = "SELECT name,email FROM members WHERE memid = '$memid'";
  if (! (@approw = $dbh->selectrow_array($sql))) {
    $dbh->disconnect;
    return 0;
  }
  $main::applicant_name = $approw[0];
  $main::applicant_email = $approw[1];
  print "Application ID: $appid, Member ID: $memid\n" if $debug;
  $dbh->disconnect;
  return 1;
}
$debug = 0;
print $argv[1], $argv[2];
if ($ARGV[0] eq '--debug') { $debug = 1; }

print "Debug Turned on\n" if $debug;

while (defined ($line = <STDIN>)) {
  if ($line =~ /SPI-NM-CHECK:\s*(\S{32})/i ) { $randkey = $1; }
  if ($line =~ /^From:\s*(\S.+)/i ) { $email = $1; }
  if ($line =~ /^Reply-To:\s*(\S.+)/i ) { $replyto = $1; }
}

$email = $replyto if $replyto;

# Debugging stuff; remove this, it's not save
#open TEST, ">> /tmp/spinm.txt";
#print TEST "Email is $email\n";
#print TEST "Randkey is $randkey\n-------\n";
#close TEST;

if ($randkey ne "" && $email ne "" ) {
  if (verify_email($email, $randkey) ) {
    send_goodemail($email);
  } else {
    send_bademail($email);
  }
} else {
  if (!$email) {
    $main::spierr .= "There was no email address. Sending to admin!\n";
    $email = "admin\@members.spi-inc.org";
 }

  if ($randkey eq "") {
     $main::spierr .= "Could not find validation key in your email.\n";
  }
  send_bademail($email);
}  


