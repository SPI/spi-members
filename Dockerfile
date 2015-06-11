# Dockerfile for SPI Membership web application

# We need a Debian 8 (jessie) base
FROM debian:jessie

MAINTAINER Jonathan McDowell

# Update the sources list + install the dependencies of the app
RUN apt-get update && apt-get install -y python python-flask \
	python-flask-login python-flaskext.wtf sqlite3 \
	apache2 libapache2-mod-wsgi

# Create a user for the app to run as.
RUN groupadd spinm && useradd -m -g spinm spinm

RUN mkdir -p /srv/members.spi-inc.org/htdocs /srv/members.spi-inc.org/spiapp \
	/srv/members.spi-inc.org/db
COPY *.py /srv/members.spi-inc.org/spiapp/
COPY templates/ /srv/members.spi-inc.org/spiapp/templates/
COPY docker-instance.cfg /srv/members.spi-inc.org/spiapp/spiapp.cfg
COPY spiapp-sqlite.sql /srv/members.spi-inc.org/spiapp/
COPY spiwebapp.wsgi /srv/members.spi-inc.org/htdocs/
COPY apache-host.conf /etc/apache2/sites-available/members.spi-inc.org.conf

# Disable the default and only only have the members site enabled.
RUN a2dissite 000-default
RUN a2ensite members.spi-inc.org

# Create the empty members database
RUN cd /srv/members.spi-inc.org/ && \
	(cat spiapp/spiapp-sqlite.sql ; echo .quit) | sqlite3 db/spiapp.db && \
	chown -R spinm db/

# We expose our webserver port
# TODO: Switch to SSL
EXPOSE 80

# Set the directory for the app
WORKDIR /srv/members.spi-inc.org/spiapp

# Start Apache
CMD /bin/bash -c "source /etc/apache2/envvars && /usr/sbin/apache2 -D FOREGROUND"
