# This Makefile should need no changes from webwml/english/logos/Makefile
# Please send a message to debian-www if you need to modify anything
# so the problem can be fixed.


HTMLFILES= 
PHPFILES=index.php newnm.php nmstatus.php logout.php getpass.php stats.php application.php mgrlist.php details.php chpass.php
INCFILES=config.inc common.inc
WMLFILES=$(wildcard *.wml)
IMAGES=$(wildcard *.gif) $(wildcard *.jpg)
SPITEMPLATEDIR=../spiwml/webwml/template
SPITEMPLATES=$(wildcard template/*.wml) $(wildcard $(SIPTEMPLATEDIR)/*.wml)

WML_DEFS= -I $(SPITEMPLATEDIR) -I template

all: $(HTMLFILES) $(PHPFILES)

%.html: %.wml $(SPITEMPLATES)
	wml $(WML_DEFS) $< -o UNDEFuEN:$@

%.php: %.wml $(SPITEMPLATES)
	wml $(WML_DEFS) $< -o UNDEFuEN:$@

rsync: $(HTMLFILES) $(PHPFILES) 
	rsync -e ssh $(HTMLFILES) $(PHPFILES) $(IMAGES) $(INCFILES) purcel.spi-inc.org:/org/nm.spi-inc.org/web

install: $(HTMLFILES) $(PHPFILES) 
	cp $(HTMLFILES) $(PHPFILES) $(IMAGES) $(INCFILES) $(TARGETDIR)

clean:
	rm -f $(PHPFILES) $(HTMLFILES)
