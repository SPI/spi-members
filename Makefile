# Please send a message to membership@spi-inc.org if you need to
# modify anything here.

FINFILES := $(wildcard finances/*.*) finances/.htaccess
WMLFILES := $(wildcard *.wml)
PHPFILES := $(WMLFILES:wml=php)
INCFILES := config.inc common.inc
SPITEMPLATEDIR := ../../www.spi-inc.org/webwml/template
SPITEMPLATES := $(wildcard template/*.wml) $(wildcard $(SPITEMPLATEDIR)/*.wml)
TARGETDIR := ../www

WML_DEFS := -I $(SPITEMPLATEDIR) -I template -DHOME="http://www.spi-inc.org" \
            -D CUR_YEAR=$(shell date +%Y) -D CUR_ISO_LANG="en"

all: $(PHPFILES) $(FINFILES)

fin:
	mkdir -p $(TARGETDIR)/finances
	cp -a $(FINFILES) $(TARGETDIR)/finances

%.html: %.wml $(SPITEMPLATES)
	wml $(WML_DEFS) $< -o UNDEFuEN:$@

%.php: %.wml $(SPITEMPLATES)
	wml $(WML_DEFS) $< -o UNDEFuEN:$@

install: all fin
	cp -a $(PHPFILES) $(INCFILES) $(TARGETDIR)/

clean:
	rm -f $(PHPFILES)
