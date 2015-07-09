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
import datetime
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
                      row['ismember'], row['sub_private'], row['createvote'],
                      row['lastactive'])

    def vote_from_db(self, row):
        """"Given a row from the vote_election table, return a Vote object"""
        owner = self.get_member_by_id(row['owner'])
        return Vote(row['ref'], row['title'], row['description'],
                    row['period_start'], row['period_stop'], owner)

    @staticmethod
    def vote_option_from_db(row, vote):
        """"Given a row from the vote_option table, return VoteOption object"""
        return VoteOption(row['ref'], vote, row['description'], row['sort'],
                          row['option_character'])

    @staticmethod
    def membervote_from_db(row, user, vote):
        """"Given a row from the vote_vote table, return a MemberVote object"""
        return MemberVote(row['ref'], user, vote, row['private_secret'],
                          row['late_updated'])

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

    def get_votes(self, active=None, owner=None):
        """Return all / only active votes from the database."""
        votes = []
        sql = "SELECT * FROM vote_election"
        if self.data['dbtype'] == 'sqlite3':
            now = "DATETIME('now')"
        elif self.data['dbtype'] == 'postgres':
            now = "'now'"

        if active is not None:
            if active:
                sql += ' WHERE period_start <= ' + now
                sql += ' AND period_stop >= ' + now
            else:
                sql += ' WHERE period_start > ' + now
                sql += ' OR period_stop < ' + now

        if owner is not None:
            if active is None:
                sql += ' WHERE'
            else:
                sql += ' AND'
            # Yes, this isn't escaped, but we know it's just a number and
            # not user supplied.
            sql += ' owner = ' + str(owner.memid)

        cur = self.data['conn'].cursor()
        cur.execute(sql)

        for row in cur.fetchall():
            votes.append(self.vote_from_db(row))
        return votes

    def get_vote(self, voteid):
        """Return requested vote from the database."""
        vote = None
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('SELECT * FROM vote_election WHERE ref = ?',
                        (voteid, ))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('SELECT * FROM vote_election WHERE ref = %s',
                        (voteid, ))

        row = cur.fetchone()
        if row:
            vote = self.vote_from_db(row)
            options = []
            if self.data['dbtype'] == 'sqlite3':
                cur.execute('SELECT * FROM vote_option ' +
                            'WHERE election_ref = ?', (voteid, ))
            elif self.data['dbtype'] == 'postgres':
                cur.execute('SELECT * FROM vote_option ' +
                            'WHERE election_ref = %s', (voteid, ))

            for row in cur.fetchall():
                options.append(self.vote_option_from_db(row, vote))

            vote.options = options

        return vote

    def create_vote(self, owner, title, description, start, end):
        """Create a new vote"""
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('INSERT INTO vote_election (ref, title, ' +
                        'description, period_start, period_stop, owner) ' +
                        'VALUES ((SELECT COALESCE(MAX(ref) + 1, 1) FROM ' +
                        'vote_election), ?, ?, ?, ?, ?)',
                        (title, description, start, end, owner.memid))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('INSERT INTO vote_election (ref, title, ' +
                        'description, period_start, period_stop, owner) ' +
                        'VALUES ((SELECT COALESCE(MAX(ref) + 1, 1) FROM ' +
                        'vote_vote), %s, %s, %s, %s, %s)',
                        (title, description, start, end, owner.memid))
        self.data['conn'].commit()

        if self.data['dbtype'] == 'sqlite3':
            cur.execute('SELECT * FROM vote_election WHERE title = ?',
                        (title, ))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('SELECT * FROM vote_election WHERE title = %s',
                        (title, ))

        row = cur.fetchone()
        if row:
            return self.vote_from_db(row)

        return None


    def update_vote(self, vote):
        """Update an existing vote"""
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('UPDATE vote_election SET title = ?, ' +
                        'description = ?, period_start = ?, ' +
                        'period_stop = ?, owner = ? WHERE ref = ?',
                        (vote.title, vote.description, vote.start, vote.end,
                         vote.owner.memid, vote.voteid))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('UPDATE vote_election SET title = %s, ' +
                        'description = %s, period_start = %s, ' +
                        'period_stop = %s, owner = %s WHERE ref = %s',
                        (vote.title, vote.description, vote.start, vote.end,
                         vote.owner.memid, vote.voteid))
        self.data['conn'].commit()

        return self.get_vote(vote.voteid)


    def delete_vote(self, voteid):
        """Delete a vote"""
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('DELETE FROM vote_option WHERE election_ref = ?',
                        (voteid, ))
            cur.execute('DELETE FROM vote_election WHERE ref = ?', (voteid, ))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('DELETE FROM vote_option WHERE election_ref = %s',
                        (voteid, ))
            cur.execute('DELETE FROM vote_election WHERE ref = %s', (voteid, ))
        self.data['conn'].commit()

        return

    def add_vote_option(self, vote, option, char, order):
        """Add a new vote option for an existing vote."""
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('INSERT INTO vote_option (ref, election_ref, ' +
                        'description, sort, option_character) ' +
                        'VALUES ((SELECT COALESCE(MAX(ref) + 1, 1) FROM ' +
                        'vote_option), ?, ?, ?, ?)',
                        (vote.voteid, option, order, char))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('INSERT INTO vote_option (ref, election_ref, ' +
                        'description, sort, option_character) ' +
                        'VALUES ((SELECT COALESCE(MAX(ref) + 1, 1) FROM ' +
                        'vote_option), %s, %s, %s, %s)',
                        (vote.voteid, option, order, char))
        self.data['conn'].commit()

        return self.get_vote(vote.voteid)


    def update_vote_option(self, voteoption):
        """Updates an existing vote option for an existing vote."""
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('UPDATE vote_option SET description = ?, ' +
                        'sort = ?, option_character = ? WHERE ref = ?',
                        (voteoption.description, voteoption.sort,
                         voteoption.char, voteoption.optionid))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('UPDATE vote_option SET description = %s, ' +
                        'sort = %s, option_character = %s WHERE ref = %s',
                        (voteoption.description, voteoption.sort,
                         voteoption.char, voteoption.optionid))
        self.data['conn'].commit()

        return self.get_vote(voteoption.vote.voteid)


    def delete_vote_option(self, voteoption):
        """
            Removes a vote option for an existing vote.
            Does not currently re-flow options to eliminate gaps.
        """
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('DELETE FROM vote_option WHERE ref = ?',
                        (voteoption.optionid, ))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('DELETE FROM vote_option WHERE ref = %s',
                        (voteoption.optionid, ))
        self.data['conn'].commit()

        return self.get_vote(voteoption.vote.voteid)


    def get_membervote(self, user, vote):
        """Return requested user's vote from the database."""
        membervote = None
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('SELECT * FROM vote_vote ' +
                        'WHERE voter_ref = ? AND election_ref = ?',
                        (user.memid, vote.voteid))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('SELECT * FROM vote_vote ' +
                        'WHERE voter_ref = %s AND election_ref = %s',
                        (user.memid, vote.voteid))

        row = cur.fetchone()
        if row:
            membervote = self.membervote_from_db(row, user, vote)
            votes = []
            if self.data['dbtype'] == 'sqlite3':
                cur.execute('SELECT * FROM vote_voteoption ' +
                            'WHERE vote_ref = ? ORDER BY preference',
                            (membervote.ref, ))
            elif self.data['dbtype'] == 'postgres':
                cur.execute('SELECT * FROM vote_voteoption ' +
                            'WHERE vote_ref = %s ORDER BY preference',
                            (membervote.ref, ))

            for row in cur.fetchall():
                votes.append(vote.option_by_ref(row['option_ref']))

            membervote.votes = votes

        return membervote

    def get_membervotes(self, vote):
        """Return all user votes for a specific vote from the database."""
        membervotes = []
        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('SELECT * FROM vote_vote WHERE election_ref = ?',
                        (vote.voteid, ))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('SELECT * FROM vote_vote WHERE election_ref = %s',
                        (vote.voteid, ))

        for vote_row in cur.fetchall():
            membervote = self.membervote_from_db(
                vote_row,
                self.get_member_by_id(vote_row['voter_ref']),
                vote)
            votes = []
            if self.data['dbtype'] == 'sqlite3':
                cur.execute('SELECT * FROM vote_voteoption ' +
                            'WHERE vote_ref = ? ORDER BY preference',
                            (membervote.ref, ))
            elif self.data['dbtype'] == 'postgres':
                cur.execute('SELECT * FROM vote_voteoption ' +
                            'WHERE vote_ref = %s ORDER BY preference',
                            (membervote.ref, ))

            for row in cur.fetchall():
                votes.append(vote.option_by_ref(row['option_ref']))

            membervote.votes = votes
            membervotes.append(membervote)

        return membervotes


    def create_membervote(self, user, vote):
        """Create a new entry for a member vote"""

        md5 = hashlib.md5()
        md5.update(vote.title)
        md5.update(user.email)
        md5.update(uuid.uuid1().hex)
        secret = md5.hexdigest()

        cur = self.data['conn'].cursor()
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('INSERT INTO vote_vote ' +
                        '(ref, voter_ref, election_ref, private_secret) ' +
                        'VALUES ((SELECT COALESCE(MAX(ref) + 1, 1) FROM ' +
                        'vote_vote), ?, ?, ?)',
                        (user.memid, vote.voteid, secret))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('INSERT INTO vote_vote ' +
                        '(ref, voter_ref, election_ref, private_secret) ' +
                        'VALUES ((SELECT COALESCE(MAX(ref) + 1, 1) FROM ' +
                        'vote_vote), %s, %s, %s)',
                        (user.memid, vote.voteid, secret))
        self.data['conn'].commit()

        return self.get_membervote(user, vote)

    def store_membervote(self, membervote):
        """Store the member's voting preference in the database."""
        cur = self.data['conn'].cursor()

        # Remove any previous vote details first
        if self.data['dbtype'] == 'sqlite3':
            cur.execute('DELETE FROM vote_voteoption WHERE vote_ref = ?',
                        (membervote.ref, ))
        elif self.data['dbtype'] == 'postgres':
            cur.execute('DELETE FROM vote_voteoption WHERE vote_ref = %s',
                        (membervote.ref, ))

        for i, option in enumerate(membervote.votes, 1):
            if self.data['dbtype'] == 'sqlite3':
                cur.execute('INSERT INTO vote_voteoption ' +
                            '(vote_ref, option_ref, preference) '
                            'VALUES (?, ?, ?)',
                            (membervote.ref, option.optionid, i))
            elif self.data['dbtype'] == 'postgres':
                cur.execute('INSERT INTO vote_voteoption ' +
                            '(vote_ref, option_ref, preference) '
                            'VALUES (%s, %s, %s)',
                            (membervote.ref, option.optionid, i))
        # update_member_field will do the commit
        self.update_member_field(membervote.user.email, 'lastactive',
                                 datetime.date.today())


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

    def can_createvote(self):
        """Is this member allowed to create votes?"""
        return self.data['createvote']

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
                 ismanager=False, ismember=False, sub_private=False,
                 createvote=False, lastactive=None):
        self.data = {}
        self.memid = memid
        self.email = email
        self.name = name
        self.firstdate = started
        self.lastactive = lastactive
        self.data['contrib'] = iscontrib
        self.data['password'] = cryptpw
        self.data['manager'] = ismanager
        self.data['member'] = ismember
        self.data['sub_private'] = sub_private
        self.data['createvote'] = createvote
    #pylint: enable=too-many-arguments

    def __trunc__(self):
        return self.memid

    def __eq__(self, other):
        return self.memid == other.memid

class Vote(object):
    """Represents an SPI vote."""
    def __init__(self, voteid, title, description, start, end, owner,
                 options=None):
        self.voteid = voteid
        self.title = title
        self.description = description
        self.start = start
        self.end = end
        self.owner = owner
        self.options = options

    def is_active(self):
        """"Check if a vote is currently active"""
        now = datetime.datetime.now()
        return self.start <= now <= self.end

    def is_over(self):
        """"Check if a voting period is over"""
        now = datetime.datetime.now()
        return now > self.end

    def is_pending(self):
        """"Check if a vote is still waiting to be active"""
        now = datetime.datetime.now()
        return now < self.start

    def option_by_ref(self, ref):
        """Returns a vote option by its reference ID"""
        # For the handful of options this is fine; a dict might be better.
        for option in self.options:
            if option.optionid == ref:
                return option
        return None

    def option_by_char(self, char):
        """Returns a vote option by its display character"""
        # For the handful of options this is fine; a dict might be better.
        for option in self.options:
            if option.char == char:
                return option
        return None


class VoteOption(object):
    """Represents an option for an SPI vote."""
    def __init__(self, optionid, vote, description, sort, char):
        self.optionid = optionid
        self.vote = vote
        self.description = description
        self.sort = sort
        self.char = char


class MemberVote(object):
    """Represents a contributing member's vote."""
    def __init__(self, ref, user, vote, secret, updated):
        self.ref = ref
        self.user = user
        self.vote = vote
        self.secret = secret
        self.updated = updated
        self.votes = None

    def votestr(self):
        """Returns a string representing the user's voting preference."""
        res = ""
        for vote in self.votes:
            res += vote.char
        return res

    def resultcookie(self):
        """Returns the user's secret cookie for voting verification."""
        md5 = hashlib.md5()
        md5.update(self.secret + " " + self.user.email + "\n")
        return md5.hexdigest()

    def set_vote(self, votestr):
        """Update the user's voting preference based on the voting string."""
        newvotes = []
        for char in votestr:
            option = self.vote.option_by_char(char)
            if option is None:
                return "Invalid vote option " + char
            newvotes.append(option)
        self.votes = newvotes


class CondorcetVS(object):
    """Implementation of the Condorcet voting system"""
    def __init__(self, vote, membervotes):
        self.vote = vote
        self.membervotes = membervotes
        # Initialise our empty beat matrix
        self.beatmatrix = {}
        for row in self.vote.options:
            self.beatmatrix[row.optionid] = {}
            for col in self.vote.options:
                self.beatmatrix[row.optionid][col.optionid] = 0
        self.tie = False
        self.winners = [None] * len(self.vote.options)
        self.wincount = {}


    def run(self):
        """Run the vote"""
        options = [option.optionid for option in self.vote.options]

        # Fill the beat matrix. bm[x][y] is the number of times x was
        # preferred over y.
        for membervote in self.membervotes:
            votecounted = {}
            for curpref, pref in enumerate(membervote.votes):
                votecounted[pref.optionid] = True
                for lesspref in membervote.votes[curpref + 1:]:
                    self.beatmatrix[pref.optionid][lesspref.optionid] += 1

        for row in options:
            wins = 0
            self.wincount[row] = {}
            for col in options:
                if row != col:
                    self.wincount[row][col] = (self.beatmatrix[row][col] -
                                               self.beatmatrix[col][row])
                    if self.wincount[row][col] > 0:
                        wins += 1

            self.wincount[row]['wins'] = wins

            if self.winners[wins]:
                self.tie = True
                self.winners[wins] += " AND "
                self.winners[wins] += self.vote.option_by_ref(row).description
            else:
                self.winners[wins] = self.vote.option_by_ref(row).description

    def results(self):
        """Return an array of the vote winners"""
        return reversed(self.winners)
