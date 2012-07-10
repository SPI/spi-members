#!/bin/sh

DATE=`date +'Membership Report for Week Ending %d %b %Y'`
/srv/members.spi-inc.org/bin/weekrpt.pl | mail -s "$DATE" members@members.spi-inc.org

