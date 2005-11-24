#!/bin/sh

DATE=`date +'Membership Report for Week Ending %d %b %Y'`
/srv/members.debian.org/bin/weekrpt.pl | mail -s "$DATE" spi-private@spi-inc.org

