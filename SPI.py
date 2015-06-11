# -*- coding: utf-8 -*-
#
# Copyright 2015 Software in the Public Interest, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
"""
    SPI
    ---

    Classes related to the handling of the Software in the Public
    Interest members database.
"""

# We'd be Python 3, but not everything we need is in Debian 8 (jessie)
from __future__ import (absolute_import, division, print_function)
#                        unicode_literals)

import crypt
import hashlib
import psycopg2
import psycopg2.extras
import random
import string
import sqlite3
import uuid


class MemberDB(object):
    """Provides the interface to the members database backend."""
    def __init__(self, dbtype, db, user=None, password=None, host=None,
                 port=None):
        self.data = {}
        self.data['dbtype'] = dbtype
        self.data['db'] = db
        if dbtype == 'sqlite3':
            self.data['conn'] = sqlite3.connect(
                self.data['db'], detect_types=sqlite3.PARSE_DECLTYPES)
            self.data['conn'].row_factory = sqlite3.Row
        elif dbtype == 'postgres':
            self.data['conn'] = psycopg2.connect(
                database=self.data['db'], user=user, password=password,
                host=host, port=port,
                cursor_factory=psycopg2.extras.DictCursor)

    def close(self):
        """Close our connection to the database."""
        self.data['conn'].close()

    def application_from_db(self, row, manager=None):
        """Return an application object for a given database result."""
        user = self.member_from_db(row)
        if not manager or manager.memid != row['manager']:
            manager = self.get_member_by_id(row['manager'])
        return Application(user, manager, row['appid'],
                           row['appdate'], row['approve'], row['approve_date'],
                           row['contribapp'],
                           row['emailkey'], row['emailkey_date'],
                           row['validemail'], row['validemail_date'],
                           row['contrib'], row['comment'], row['manager_date'],
                           row['lastchange'])

    @staticmethod
    def member_from_db(row):
        """Given a row dict from the members table, return a Member object"""
        return Member(row['memid'], row['email'], row['name'], row['password'],
                      row['firstdate'], row['iscontrib'], row['ismanager'],
                      row['ismember'], row['sub_private'])

    def verify_email(self, user, emailkey):
        """Check emailkey against the database and mark valid if correct"""
        result = None
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('SELECT appid, validemail FROM applications ' +
                        'WHERE member = ? AND emailkey = ?',
                        (user.memid, emailkey))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('SELECT appid, validemail FROM applications ' +
                        'WHERE member = %s AND emailkey = %s',
                        (user.memid, emailkey))
        row = cur.fetchone()
        if row:
            if row['validemail']:
                result = "Email address already verified."
            else:
                if self.data['dbtype'] == 'sqlite3':
                    cur.execute('UPDATE applications SET validemail = 1, ' +
                                'validemail_date = date(\'now\'), ' +
                                'lastchange = date(\'now\')' +
                                'WHERE appid = ?',
                                (row['appid'], ))
                elif self.data['dbtype'] == 'postgres':
                    cur.execute('UPDATE applications SET validemail = true, ' +
                                'validemail_date = date(\'now\'), ' +
                                'lastchange = date(\'now\')' +
                                'WHERE appid = %s',
                                (row['appid'], ))
                # update_member_field will handle the commit
                self.update_member_field(user.email, 'ismember', True)
        else:
            result = "Application not found."
        return result

    def get_member(self, userid):
        """Retrieve a member object from the database by email address"""
        user = None
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('SELECT * FROM members WHERE email = ?', (userid, ))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('SELECT * FROM members WHERE email = %s', (userid, ))
        row = cur.fetchone()
        if row:
            user = self.member_from_db(row)
        return user

    def get_member_by_id(self, memid):
        """Retrieve a member object from the database by member ID"""
        if memid in [None, 0]:
            return None
        user = None
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('SELECT * FROM members WHERE memid = ?', (memid, ))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('SELECT * FROM members WHERE memid = %s', (memid, ))
        row = cur.fetchone()
        if row:
            user = self.member_from_db(row)
        return user

    def update_member_field(self, userid, field, data):
        """Update a single field in the database for a given member"""
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('UPDATE members SET ' + field + ' = ? WHERE email = ?',
                        (data, userid))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('UPDATE members SET ' + field +
                        ' = %s WHERE email = %s',
                        (data, userid))
        self.data['conn'].commit()

    def get_applications(self, manager=None):
        """Get all applications, optionally only for a given manager."""
        applications = []
        cur = self.data['conn'].cursor()
        if manager:
            if self.data['dbtype'] == 'sqlite3':
                cur.execute('SELECT a.*, m.* from applications a, members m ' +
                            'WHERE m.memid = a.member AND a.manager = ? ' +
                            'ORDER BY a.appdate', (manager.memid, ))
            elif self.data['dbtype'] == 'postgres':
                cur.execute('SELECT a.*, m.* from applications a, members m ' +
                            'WHERE m.memid = a.member AND a.manager = %s ' +
                            'ORDER BY a.appdate', (manager.memid, ))
        else:
            cur.execute('SELECT a.*, m.* from applications a, members m ' +
                        'WHERE m.memid = a.member ORDER BY a.appdate')
        for row in cur.fetchall():
            if not manager or manager.memid != row['manager']:
                manager = self.get_member_by_id(row['manager'])
            applications.append(self.application_from_db(row))
        return applications

    def get_applications_by_user(self, user):
        """Retrieve all applications for the supplied user."""
        applications = []
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('SELECT a.*, m.* from applications a, members m ' +
                        'WHERE m.memid = a.member AND m.memid = ? ' +
                        'ORDER BY a.appdate', (user.memid, ))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('SELECT a.*, m.* from applications a, members m ' +
                        'WHERE m.memid = a.member AND m.memid = %s ' +
                        'ORDER BY a.appdate', (user.memid, ))
        for row in cur.fetchall():
            applications.append(self.application_from_db(row))
        return applications

    def get_applications_by_type(self, listtype):
        """Retrieve all applications of a given type."""
        applications = []
        manager = None

        if self.data['dbtype'] == 'sqlite3':
            t = '1'
            f = '0'
        elif self.data['dbtype'] == 'postgres':
            t = 'true'
            f = 'false'

        if listtype == 'nca':
            where = 'AND (m.ismember = ' + f + ' OR m.ismember IS NULL)'
        elif listtype == 'ncm':
            where = ('AND m.ismember = ' + t + ' AND m.iscontrib = ' + f +
                     ' AND (contribapp = ' + f + ' OR contribapp IS NULL)')
        elif listtype == 'ca':
            where = ('AND m.ismember = ' + t + ' AND a.approve IS NULL AND ' +
                     'contribapp = ' + t + '')
        elif listtype == 'cm':
            where = ('AND m.ismember = ' + t + ' AND m.iscontrib = ' + t +
                     ' AND contribapp = ' + t)
        elif listtype == 'mgr':
            where = ('AND m.ismember = ' + t + ' AND m.ismanager = ' + t +
                     ' AND contribapp = ' + t)
        else:
            where = ''

        cur = self.data['conn'].cursor()
        cur.execute('SELECT a.*, m.* from applications a, members m ' +
                    'WHERE m.memid = a.member ' + where +
                    ' ORDER BY a.appdate')
        for row in cur.fetchall():
            if not manager or manager.memid != row['manager']:
                manager = self.get_member_by_id(row['manager'])
            applications.append(self.application_from_db(row))
        return applications

    def get_application(self, appid):
        """Retrieve application by application ID."""
        application = None
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('SELECT a.*, m.* from applications a, members m ' +
                        'WHERE m.memid = a.member AND a.appid = ?', (appid, ))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('SELECT a.*, m.* from applications a, members m ' +
                        'WHERE m.memid = a.member AND a.appid = %s', (appid, ))
        row = cur.fetchone()
        if row:
            application = self.application_from_db(row)
        return application

    def create_application(self, name, email, password):
        """Create a new non-contributing membership application."""
        user = self.get_member(email)
        if user:
            return None

        md5 = hashlib.md5()
        md5.update(email)
        md5.update(uuid.uuid1().hex)
        emailkey = md5.hexdigest()

        chars = string.letters + string.digits
        salt = random.choice(chars) + random.choice(chars)
        cryptpw = crypt.crypt(password, salt)
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('INSERT INTO members (name, email, password, ' +
                        'firstdate, ismember, iscontrib, ismanager) VALUES ' +
                        '(?, ?, ?, date(\'now\'), 0, 0, 0)',
                        (name, email, cryptpw))
            cur.execute('INSERT INTO applications (appdate, member, ' +
                        'contribapp, emailkey, emailkey_date, lastchange) ' +
                        'SELECT date(\'now\'), memid, 0, ?, date(\'now\'), ' +
                        'date(\'now\') FROM members WHERE email = ?',
                        (emailkey, email))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('INSERT INTO members (name, email, password, ' +
                        'firstdate, ismember, iscontrib, ismanager) VALUES ' +
                        '(%s, %s, %s, date(\'now\'), false, false, false)',
                        (name, email, cryptpw))
            cur.execute('INSERT INTO applications (appdate, member, ' +
                        'contribapp, emailkey, emailkey_date, lastchange) ' +
                        'SELECT date(\'now\'), memid, false, %s, ' +
                        'date(\'now\'), date(\'now\') FROM members ' +
                        'WHERE email = %s', (emailkey, email))
        self.data['conn'].commit()

        if self.data['dbtype'] == 'sqlite3':
            cur.execute('SELECT a.*, m.* from applications a, members m ' +
                        'WHERE m.memid = a.member AND m.email = ?', (email, ))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('SELECT a.*, m.* from applications a, members m ' +
                        'WHERE m.memid = a.member AND m.email = %s', (email, ))
        row = cur.fetchone()
        if row:
            application = self.application_from_db(row)
        return application

    def create_contrib_application(self, user, contrib, sub_private):
        """Create a new application for contributing member status."""
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('INSERT INTO applications (appdate, member, ' +
                        'contribapp, lastchange, contrib) VALUES ' +
                        '(date(\'now\'), ?, 1, date(\'now\'), ?)',
                        (user.memid, contrib))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('INSERT INTO applications (appdate, member, ' +
                        'contribapp, lastchange, contrib) VALUES ' +
                        '(date(\'now\'), %s, true, date(\'now\'), %s)',
                        (user.memid, contrib))
        # update_member_field will handle the commit
        self.update_member_field(user.email, 'sub_private', sub_private)

        if self.data['dbtype'] == 'sqlite3':
            cur.execute('SELECT a.*, m.* from applications a, members m ' +
                        'WHERE m.memid = a.member AND m.email = ?',
                        (user.email, ))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('SELECT a.*, m.* from applications a, members m ' +
                        'WHERE m.memid = a.member AND m.email = %s',
                        (user.email, ))

        row = cur.fetchone()
        if row:
            application = self.application_from_db(row)
        return application

    def update_application_field(self, appid, field, data):
        """Update a single field in the database for a given application."""
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('UPDATE applications SET ' + field + ' = ? ' +
                        'WHERE appid = ?', (data, appid))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('UPDATE applications SET ' + field + ' = %s ' +
                        'WHERE appid = %s', (data, appid))
        self.data['conn'].commit()

    def update_application(self, application):
        """Update all manager editable fields for an application."""
        if application.manager:
            managerid = application.manager.memid
        else:
            managerid = None
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('UPDATE applications SET manager = ?, ' +
                        'manager_date = ?, comment = ?, approve = ?, ' +
                        'approve_date = ?, lastchange = date(\'now\') ' +
                        ' WHERE appid = ?',
                        (managerid, application.manager_date,
                         application.comment, application.approve,
                         application.approve_date, application.appid))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('UPDATE applications SET manager = %s, ' +
                        'manager_date = %s, comment = %s, approve = %s, ' +
                        'approve_date = %s, lastchange = date(\'now\') ' +
                        ' WHERE appid = %s',
                        (managerid, application.manager_date,
                         application.comment, application.approve,
                         application.approve_date, application.appid))
        self.data['conn'].commit()


class Application(object):
    """Represents an application to become an SPI member."""
    #pylint: disable=too-many-arguments
    def __init__(self, user, manager, appid, appdate, approve, approve_date,
                 contribapp, emailkey, emailkey_date, validemail,
                 validemail_date, contrib, comment, manager_date, lastchange):
        self.user = user
        self.manager = manager
        self.appid = appid
        self.appdate = appdate
        self.approve = approve
        self.approve_date = approve_date
        self.contribapp = contribapp
        self.emailkey = emailkey
        self.emailkey_date = emailkey_date
        self.validemail = validemail
        self.validemail_date = validemail_date
        self.contrib = contrib
        self.comment = comment
        self.manager_date = manager_date
        self.sub_private = user.sub_private()
        self.lastchange = lastchange
    #pylint: enable=too-many-arguments

    def get_status(self):
        """Return the member status for this application"""
        if self.user.is_contrib():
            return 'CM'
        elif self.contribapp:
            return 'CA'
        elif self.approve:
            return 'NCM'
        else:
            return 'NCA'


class Member(object):
    """Represents a member of SPI."""
    @staticmethod
    def is_authenticated():
        """If we have a Member object, it's authenticated."""
        return True

    @staticmethod
    def is_active():
        """SPI members are all active users (maybe with limited rights)."""
        return True

    @staticmethod
    def is_anonymous():
        """SPI members are not anonymous."""
        return False

    def get_id(self):
        """Use email address as the ID for retrieval by Flask."""
        return self.email

    def is_contrib(self):
        """Is the member an SPI contributing member?"""
        return self.data['contrib']

    def is_manager(self):
        """Is the member an application manager?"""
        return self.data['manager']

    def is_member(self):
        """Is this a valid SPI member (contributing or non-contributing)?"""
        return self.data['member']

    def sub_private(self):
        """Should the member be subscribed to spi-private?"""
        if self.data['sub_private'] in [1, 'true', True]:
            return True
        elif self.data['sub_private'] in [0, 'false', False]:
            return False
        else:
            return None

    def validate_password(self, password):
        """Check that the supplied password is correct for this member."""
        return crypt.crypt(password,
                           self.data['password']) == self.data['password']

    def set_password(self, dbh, password):
        """Change the password for this member."""
        chars = string.letters + string.digits
        salt = random.choice(chars) + random.choice(chars)
        cryptpw = crypt.crypt(password, salt)

        dbh.update_member_field(self.email, 'password', cryptpw)

        return True

    #pylint: disable=too-many-arguments
    def __init__(self, memid, email, name, cryptpw, started, iscontrib=False,
                 ismanager=False, ismember=False, sub_private=False):
        self.data = {}
        self.memid = memid
        self.email = email
        self.name = name
        self.firstdate = started
        self.data['contrib'] = iscontrib
        self.data['password'] = cryptpw
        self.data['manager'] = ismanager
        self.data['member'] = ismember
        self.data['sub_private'] = sub_private
    #pylint: enable=too-many-arguments

    def __trunc__(self):
        return self.memid

    def __eq__(self, other):
        return self.memid == other.memid
