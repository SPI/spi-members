# Please send a message to new-member@spi-inc.org if you need to modify
# anything here.

WMLFILES := $(wildcard *.wml)
PHPFILES := $(WMLFILES:wml=php)
INCFILES := config.inc common.inc
SPITEMPLATEDIR := ../../www.spi-inc.org/webwml/template
SPITEMPLATES := $(wildcard template/*.wml) $(wildcard $(SPITEMPLATEDIR)/*.wml)
TARGETDIR := ../www

WML_DEFS := -I $(SPITEMPLATEDIR) -I template -DHOME="http://www.spi-inc.org" \
            -D CUR_YEAR=$(shell date +%Y) -D CUR_ISO_LANG="en"

all: $(PHPFILES)

%.html: %.wml $(SPITEMPLATES)
	wml $(WML_DEFS) $< -o UNDEFuEN:$@

%.php: %.wml $(SPITEMPLATES)
	wml $(WML_DEFS) $< -o UNDEFuEN:$@

install: all
	cp -a $(PHPFILES) $(INCFILES) $(TARGETDIR)/

clean:
	rm -f $(PHPFILES)
