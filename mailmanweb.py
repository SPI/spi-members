#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2016 Software in the Public Interest, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#

"""
    Module to talk to Mailman's web interface
    Primarily meant to deal with subscriber lists
"""

# We'd be Python 3, but not everything we need is in Debian 8 (jessie)
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

import cookielib
import httplib
import re
import urllib
import urllib2

from bs4 import BeautifulSoup


class MailmanWeb(object):
    """Provides an interface to the Mailman web interface."""
    def __init__(self, baseurl, listname):
        self.data = {}
        self.data['baseurl'] = baseurl
        self.data['listname'] = listname

    def login(self, password):
        """Login to the Mailman web interface"""
        policy = cookielib.DefaultCookiePolicy(rfc2965=True)
        cookiejar = cookielib.CookieJar(policy)
        self.data['opener'] = urllib2.build_opener(
            urllib2.HTTPCookieProcessor(cookiejar)).open
        url = '%s/%s' % (self.data['baseurl'], self.data['listname'])
        form = {'adminpw': password}
        try:
            page = self.data['opener'](url, urllib.urlencode(form))
        except (urllib2.URLError, httplib.InvalidURL), e:
            return False

        return True

    def subscribers(self):
        """Retrieve the list of email addresses subscribed to the list"""
        roster_url = '%s/%s' % (re.sub('admin', 'roster',
                                       self.data['baseurl']),
                                self.data['listname'])
        try:
            page = self.data['opener'](roster_url)
        except (urllib2.URLError, httplib.InvalidURL), e:
            return None

        emails = []
        soup = BeautifulSoup(page.read(), 'lxml')
        # There are 2 lists; non-digest and digest. Extract them both.
        for addresslist in soup.find_all('ul'):
            for address in addresslist.find_all('li'):
                for element in address.find_all('a'):
                    emails.append(element.get_text())

        return emails

    def add_subscribers(self, emails):
        """Subscribe the supplied list of email addresses to the list"""
        add_url = '%s/%s/members/add' % (self.data['baseurl'],
                                         self.data['listname'])

        form = {
            'subscribe_or_invite': 0,
            'send_welcome_msg_to_this_batch': 1,
            'send_notifications_to_list_owner': 0,
        }

        form['subscribees'] = '\n'.join(emails)

        try:
            page = self.data['opener'](add_url, urllib.urlencode(form))
        except (urllib2.URLError, httplib.InvalidURL), e:
            return False

        return True

    def remove_subscribers(self, emails):
        """Unsubscribe the supplied list of email addresses from the list"""
        remove_url = '%s/%s/members/remove' % (self.data['baseurl'],
                                               self.data['listname'])

        form = {
            'send_unsub_ack_to_this_batch': 0,
            'send_unsub_notifications_to_list_owner': 0,
        }

        form['unsubscribees'] = '\n'.join(emails)

        try:
            page = self.data['opener'](remove_url, urllib.urlencode(form))
        except (urllib2.URLError, httplib.InvalidURL), e:
            return False

        return True
