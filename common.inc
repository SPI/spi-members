<?
  #Common functions used everywhere
  if (!function_exists(pg_connect)) {
    dl("pgsql.so");
  }

  # Opens the Database, returns the database handle if ok and FALSE if there
  # was a problem.
  function open_db()
  {
    global $DBName, $DBUser, $DBPasswd;

    $connstr = "dbname=$DBName user=$DBUser";
    if ($DBPasswd != "") {
      $connstr .= " password=$DBPasswd";
    }
    if (! ($db = pg_Connect($connstr))) {
      echo "<STRONG>Problem with connecting to database: ", pg_ErrorMessage($db), "</STRONG><BR>";
      return FALSE;
    }
    return $db;
  }

  # check the username and password are valid
  # 0 = not found or error
  # 1 = found
  # 2 = found and they are a application manager
  function check_login($db, $email, $passwd) 
  {
    $sql = "SELECT * from members WHERE email = '$email'";
    if (! ($query = pg_exec($db, $sql))) {
      echo "Problem with query", pg_ErrorMessage($db), "<BR>";
      return 0;
    }
    if (pg_NumRows($query) != 1) {
      return 0;
    }
    $row = pg_Fetch_Array($query, 0);
    $salt = substr($row['password'], 0, 2);
    if ($row['password'] != crypt($passwd, $salt)) {
      return 0;
    }
    if ($row['ismanager'] == 't') {
      return 2;
    }
    return 1;
  }

    
  function print_bool($title, $name, $value, $editable)
  {
    echo "<TR><TD width=\"200\"><B>$title</B> </TD><TD width=\"200\">";
    if ($editable) {
	echo "<INPUT type=\"radio\" name=\"form[$name]\" value=\"t\""; 
	if ($value == 't') { echo " checked"; }
	echo ">Yes &nbsp;\n<INPUT type=\"radio\" name=\"form[$name]\" value=\"f\"";
	if ($value == 'f') { echo " checked"; }
	echo "> No &nbsp;\n<INPUT type=\"radio\" name=\"form[$name]\" value=\"n\"";
	if ($value != 'f' && $value != 't') { echo " checked"; }
	echo "> Not checked\n";
    } else {
      if ($value == 't') { echo "[ Yes ]"; }
      if ($value == 'f') { echo "[ No ]"; }
      if ($value == 'n') { echo "[ Not Checked ]"; }
    }
    echo "</TD></TR>\n";
  }
  function print_text($title, $name, $value, $editable)
  {
    echo "<TR><TD width=\"200\"><B>$title</B> </TD><TD width=\"400\"> ";
    if ($editable) {
      echo "<INPUT type=\"text\" name=\"form[$name]\" value=\"$value\">";
    } else {
      echo "[ $value ]";
    }
    echo "</TD></TR>\n";
  }
  function print_textbox($title, $name, $value, $editable)
  {
    echo "<TR><TD width=\"200\"><B>$title</B> </TD><TD width=\"400\"> ";
    if ($editable) {
      echo "<textarea name=\"form[$name]\" rows=\"5\" cols=\"30\">$value </textarea>";
    } else {
      echo "<QUOTE>$value</QUOTE>";
    }
    echo "</TD></TR>\n";
  }
  function print_checkbox($title, $name, $value, $editable)
  {
    echo "<TR><TD width=\"200\"><B>$title</B> </TD><TD width=\"400\"> ";
    if ($editable) {
      echo "<INPUT type=\"checkbox\" name=\"form[$name]\" value=\"t\" ";
      if ($value == 't') { echo "CHECKED"; }
      echo ">";
    } else {
      if ($value == 't') {
        echo "[ Yes ]";
      } else {
        echo "[ No ]";
      }
    }
    echo "</TD></TR>\n";
  }
  function print_passwd($title, $name)
  {
    echo "<TR><TD width=\"200\"><B>$title</B> </TD><TD width=\"400\"> <INPUT type=\"password\" name=\"form[$name]\"></TD></TR>\n";
  }
  function print_flag($value,$trueflag,$falseflag)
  {
    if ($value == 't') {
      echo $trueflag;
    } else {
      echo $falseflag;
    }
  }
  function get_text($name, $value)
  {
    if ($value == "" ) {
      $str = $name . "= null";
    } else {
      if (trim($value) == "today") {
        $str = $name . "='now'::date";
      } else {
        $str = $name . "='" . trim(strip_tags($value)) . "'";
      }
    }
    return $str;
  }
  function get_bool($name, $value)
  {
    if ($value == 't')
    {
      $str = $name . "= true ";
    } else if ($value == 'f') {
      $str = $name . " = false ";
    } else {
      $str = $name . " = null ";
    }
    return $str;
  }
  function get_textarea($name, $value)
  {
    if ($value == "" ) {
      $str = $name . "= null";
    } else {
      $str = $name . "='" . trim(strip_tags($value)) . "'";
    }
    return $str;
  }

function get_manager($db, $manager) {
      if (!$manager) return "none";

      $sql = "SELECT email FROM members WHERE memid = '$manager'";
      if (! ($query = pg_exec($db, $sql))) {
          return "DB error";
      }

      if (pg_NumRows($query) != 1) {
          return "unknown";
      } else {
          $row = pg_Fetch_Row($query, 0);
	  return $row[0];
      }
}

function print_applicants($sql) {
  if (! ($db = open_db())) {
    return FALSE;
  }
  if (! ($query = pg_exec($db, $sql))) {
    echo "Problem with query", pg_ErrorMessage($db), "<BR>";
    pg_Close($db);
    return FALSE;
  }
  $rows = pg_NumRows($query);
  if ($rows == 0) {
    echo "<p>None Found.</p>\n";
  } else {
      echo "<TABLE border=\"0\" summary=\"\">\n<TR><TH>Appl Date</TH><TH>Status</TH><TH>Applicant</TH><TH>App#</TH><TH>Manager</TH></TR>\n";
    for ($i = 0 ; $i < $rows ; $i++) {
      $row = pg_Fetch_Array($query, $i);
      echo "<TR><TD>", $row["appdate"], "</TD>";
      if ($row['ismember'] != 't') {
        echo "<td>NCA</td>";
      } else {
        if ($row['iscontrib'] == 'f') {
	  if ($row['approve'] == '' && $row['contribap'] == 't') {
	    echo "<td>CA</td>";
	  } else {
	    echo "<td>NCM</td>";
	  }
	} else {
	  echo "<td>CM</td>";
	}
      }

      echo "<TD><A href=\"details.php?"; ?><?=SID?><?;
      echo "&user=", urlencode($row["email"]), "\">",
            $row["name"], " &lt;",
  	    $row["email"], "&gt;</A>",
            " </TD><TD>", $row["appid"],
	    " </td><td>", get_manager($db, $row["manager"]), "</TD></TR>\n";

    }
    echo "</table>\n";
  }
  pg_Close($db);
  return TRUE;
}

function print_applications($db, $sql, $email) {
  if (! ($query = pg_exec($db, $sql))) {
    echo "Problem with query", pg_ErrorMessage($db), "<BR>";
    pg_Close($db);
    return FALSE;
  }
  $rows = pg_NumRows($query);
  for ($i = 0 ; $i < $rows ; $i++) {
    $row = pg_Fetch_Array($query, $i);
    if ($row['contribapp'] == 't') { 
      echo "Contrib application"; 
    } else {
      echo "Non-Contrib application";
    }
    echo "<A href=\"application.php?"; ?><?=SID?><?;
    echo "&appid=", urlencode($row["appid"]), "&user=", urlencode($email), "\">";
    echo "#". $row['appid'];
    echo " from ", $row['appdate'], "</a> ";
    if ($row['contribapp'] == 't') { 
      if ($row['approve'] != '') {
        echo ' (complete) ';
      }
    } else {
      if ($row['validemail'] == 't') {
        echo ' (complete) ';
      }
    }
    echo "<BR>\n";
  }
  pg_Close($db);
  return TRUE;
}
?>


