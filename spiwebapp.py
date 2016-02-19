#!/usr/bin/python
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
    Web application handling SPI Membership.
    Covers application for membership + approval of said applications.
"""

# We'd be Python 3, but not everything we need is in Debian 8 (jessie)
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

import datetime
import email
import email.header
import random
import string
import smtplib

from email.mime.text import MIMEText
from flask import (Flask, render_template, redirect, request, url_for, flash,
                   abort, g, Response)
from flask_login import (LoginManager, login_required, login_user, logout_user,
                         current_user)
from flask_wtf import Form
from urlparse import urlparse, urljoin
from wtforms import (StringField, PasswordField, BooleanField, SelectField,
                     TextAreaField, ValidationError, HiddenField)
from wtforms.validators import (DataRequired, EqualTo, Email, Optional)
from wtforms.ext.dateutil.fields import DateField, DateTimeField

import SPI

email.charset.add_charset('utf-8', email.charset.SHORTEST, email.charset.QP)

#
# Data entry WTF form classes
#


class LoginForm(Form):
    """Form handling user logins"""
    username = StringField('Email address',
                           validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

    def get_user(self):
        """Retrieve a user object based on the form data."""
        user = get_db().get_member(self.username.data)
        if user:
            if not user.validate_password(self.password.data):
                user = None
        return user


class ApplicationForm(Form):
    """Form handling non-contributing applications"""
    name = StringField('Name', validators=[DataRequired()])
    username = StringField('Email address',
                           validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Confirm Password',
                            validators=[DataRequired(), EqualTo('password')])

    def get_application(self):
        """Retrieve an application object based on the form data."""
        user = get_db().get_member(self.username.data)
        if user:
            flash('A user with that email address already exists.')
            return None

        return get_db().create_application(self.name.data, self.username.data,
                                           self.password.data)


class ContribApplicationForm(Form):
    """Form handling contributing applications"""
    contrib = TextAreaField('Contributions', validators=[DataRequired()])
    sub_private = BooleanField('Subscribe to spi-private?')


class MgrContribApplicationForm(ContribApplicationForm):
    """Form handling the management of a contributing application"""
    manager = SelectField("Manager", coerce=int)
    manager_date = DateField('Date Assigned',
                             validators=[Optional()],
                             display_format='%Y-%m-%d')
    comment = TextAreaField('Mgr Comments')
    approve = SelectField('Approved',
                          choices=[('1', 'Yes'), ('0', 'No'), ('None', '---')])
    approve_date = DateField('Date Approved',
                             validators=[Optional()],
                             display_format='%Y-%m-%d')


class EmailVerificationForm(Form):
    """Form for handling email verification"""
    emailkey = StringField('Verification code', validators=[DataRequired()])


class PWChangeForm(Form):
    """Form for handling password changes"""
    oldpw = PasswordField('Old Password', validators=[DataRequired()])
    newpw = PasswordField('New Password', validators=[DataRequired()])
    pwconfirm = PasswordField('Confirm New Password',
                              validators=[DataRequired(), EqualTo('newpw')])


class PWResetForm(Form):
    """Form for handling password resets"""
    email = StringField('Email address', validators=[DataRequired(), Email()])


class VotingForm(Form):
    """Form for handling votes"""
    vote = StringField('Vote', validators=[DataRequired()])


class VoteCreationForm(Form):
    """Form for creating/editing a new vote"""
    title = StringField('Vote title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    start = DateTimeField('Start date', validators=[DataRequired()])
    end = DateTimeField('End date', validators=[DataRequired()])

    def validate_start(self, field):
        """Verify that the start date is in the future"""
        if field.data <= datetime.datetime.now():
            raise ValidationError('Start time must be in the future')

    def validate_end(self, field):
        """Verify that the end date is in the future and after the start"""
        if field.data <= datetime.datetime.now():
            raise ValidationError('End time must be in the future')

        if field.data <= self.start.data:
            raise ValidationError('End time must be after start time')


class VoteOptionForm(Form):
    """"Form for creating/editing a vote option"""
    option = StringField('Vote option')
    char = StringField('Vote character', validators=[DataRequired()])
    order = HiddenField('order')


#
# Actual app / URL handlers below here
#

app = Flask(__name__)
app.config.from_envvar('SPIAPP_CONFIG')
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True
login_manager = LoginManager()
login_manager.init_app(app)


def is_safe_url(target):
    """Test that a URL is on our site and safe to redirect to."""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (test_url.scheme in ('http', 'https') and
            ref_url.netloc == test_url.netloc)


def get_db():
    """Retrieve a database object, creating it if necessary."""
    dbh = getattr(g, '_database', None)
    if dbh is None:
        for key in ['DB_USER', 'DB_PASS', 'DB_HOST', 'DB_PORT']:
            if key not in app.config:
                app.config[key] = None
        dbh = g._database = SPI.MemberDB(app.config['DB_TYPE'],
                                         app.config['DB_NAME'],
                                         user=app.config['DB_USER'],
                                         password=app.config['DB_PASS'],
                                         host=app.config['DB_HOST'],
                                         port=app.config['DB_PORT'])
    return dbh


@app.teardown_appcontext
def close_db(exception):
    """Clean up the database connection if necessary on request termination."""
    dbh = getattr(g, '_database', None)
    if dbh is not None:
        dbh.close()


@login_manager.user_loader
def load_user(userid):
    """Load the Member object from the database by email"""
    user = get_db().get_member(userid)
    if user:
        return user
    else:
        return None


@login_manager.unauthorized_handler
def unauthorized_callback():
    """Handler for non-logged in attempts; do login and redirect back"""
    return redirect('/login?next=' + request.path)


@app.route("/applications/<listtype>")
@login_required
def list_applications(listtype):
    """Handler for listing applications; managers only."""
    if not current_user.is_manager():
        return render_template('manager-only.html')

    if listtype not in ['all', 'nca', 'ncm', 'ca', 'cm', 'mgr']:
        flash('Unknown application type!')
        return redirect(url_for('mainpage'))

    return render_template('applications.html', db=get_db(), listtype=listtype)


def changed_date(field, formdate):
    """Return the appropriate update date for field"""
    if not field:
        return None
    elif not formdate:
        return datetime.date.today()
    else:
        return formdate


def process_contrib_application(form, application):
    """Deals with changes to a contributing application by a manager"""
    changed = False

    if form.manager.data != application.manager:
        changed = True
        application.manager = get_db().get_member_by_id(
            form.manager.data)
        application.manager_date = changed_date(application.manager,
                                                form.manager_date.data)
    elif (form.manager_date.data and
          form.manager_date.data != application.manager_date):
        changed = True
        application.manager_date = form.manager_date.data

    if form.comment.data != application.comment:
        changed = True
        application.comment = form.comment.data

    sendwelcome = False
    if form.approve.data == 'None':
        approve = None
    else:
        approve = (form.approve.data == '1')
    if approve != application.approve:
        changed = True
        if approve:
            sendwelcome = True
        application.approve = approve
        application.approve_date = changed_date(application.approve,
                                                form.approve_date.data)
    elif (form.approve_date.data and
          form.approve_date.data != application.approve_date):
        changed = True
        application.approve_date = form.approve_date.data

    if changed:
        get_db().update_application(application)
        if sendwelcome:
            get_db().update_member_field(application.user.email,
                                         'iscontrib',
                                         True)
            get_db().update_member_field(current_user.email, 'lastactive',
                                 datetime.date.today())
            flash('Applicant become a Contributing member, ' +
                  'emailing them.')
            # Send the welcome confirmation email
            msg = MIMEText(render_template('contrib-email.txt',
                                           application=application),
                           'plain', 'utf-8')
            msg['Subject'] = email.header.Header('SPI Contributing Member ' +
                                                 'application for ' +
                                                 application.user.name,
                                                 'utf-8')
            msg['From'] = ('SPI Membership Committee ' +
                           '<membership@spi-inc.org>')
            msg['To'] = application.user.email
            try:
                smtp = smtplib.SMTP(app.config['SMTP_SERVER'])
                smtp.sendmail('membership@spi-inc.org',
                              [application.user.email], msg.as_string())
                smtp.quit()
            except:
                flash('Unable to send contributing member confirmation email.')


@app.route("/application/<int:appid>", methods=['GET', 'POST'])
@login_required
def view_application(appid):
    """Handler for viewing a specific application."""
    application = get_db().get_application(appid)

    # You can only see applications if you're a manager, or it's an
    # application you submitted.
    if (not (current_user.is_manager() or (application and
                                           application.user == current_user))):
        return render_template('manager-only.html')

    if not application:
        flash('Unknown application ID!')
        return redirect(url_for('mainpage'))

    # What you can edit depends on if it's a manager or the submitting member
    # who is viewing the application form.
    if current_user.is_manager():
        mgrs = get_db().get_applications_by_type('mgr')
        form = MgrContribApplicationForm(request.form, application)
        if (not application.manager or
                application.manager in [(mgr.user) for mgr in mgrs]):
            form.manager.choices = ([(0, 'None')] +
                                    [(mgr.user.memid, mgr.user.name)
                                     for mgr in mgrs])
        else:
            # Current manager is no longer a manager, so make sure they're
            # still included in the list.
            form.manager.choices = ([(0, 'None'), (application.manager.memid,
                                                   application.manager.name)] +
                                    [(mgr.user.memid, mgr.user.name)
                                     for mgr in mgrs])
    else:
        form = ContribApplicationForm(request.form, application)

    if form.validate_on_submit():
        if form.sub_private.data != application.user.sub_private():
            get_db().update_member_field(application.user.email, 'sub_private',
                                         form.sub_private.data)

        if form.contrib.data != application.contrib:
            get_db().update_application_field(application.appid, 'contrib',
                                              form.contrib.data)

        # Deal with changes that are only possible from a manager
        if current_user.is_manager():
            process_contrib_application(form, application)

    return render_template('application.html', application=application,
                           form=form)


@app.route('/apply/contrib', methods=['GET', 'POST'])
@login_required
def applycontrib():
    """Handler for contributing membership application."""
    if current_user.is_contrib():
        flash('You are already an SPI contributing member.')
        return redirect(url_for('mainpage'))

    applications = get_db().get_applications_by_user(current_user)
    if not current_user.is_contrib():
        for apps in applications:
            if apps.contribapp and apps.approve is None:
                flash('You already have an outstanding SPI contributing ' +
                      'membership application.')
                return redirect(url_for('mainpage'))

    form = ContribApplicationForm()
    if form.validate_on_submit():
        application = get_db().create_contrib_application(
            current_user, form.contrib.data, form.sub_private.data)
        get_db().update_member_field(current_user.email, 'lastactive',
                                     datetime.date.today())
        if application:
            return redirect(url_for('mainpage'))
        flash('Error creating contributing member application.')

    return render_template('contrib-application.html', form=form)


@app.route("/votes")
@login_required
def list_votes():
    """Handler for listing votes"""

    if not current_user.is_contrib():
        return render_template('contrib-only.html')

    votes = get_db().get_votes()

    return render_template('votes.html', votes=votes)


@app.route("/vote/<int:voteid>", methods=['GET', 'POST'])
@login_required
def view_vote(voteid):
    """Handler for viewing a specific vote."""

    if not current_user.is_contrib():
        return render_template('contrib-only.html')

    vote = get_db().get_vote(voteid)

    if not vote:
        flash('Unknown vote ID!')
        return redirect(url_for('mainpage'))

    membervote = get_db().get_membervote(current_user, vote)

    form = VotingForm()

    if form.validate_on_submit():
        if not vote.is_active():
            flash('Vote is not currently running.')
        elif membervote is None:
            membervote = get_db().create_membervote(current_user, vote)

        if vote.is_active() and membervote:
            if form.vote.data != membervote.votestr():
                res = membervote.set_vote(form.vote.data)
                if isinstance(res, basestring):
                    flash(res)
                else:
                    get_db().store_membervote(membervote)

    if membervote:
        form.vote.data = membervote.votestr()

    return render_template('vote.html', form=form,
                           membervote=membervote, vote=vote)


@app.route("/vote/<int:voteid>/result")
@login_required
def view_vote_result(voteid):
    """Handler for viewing a specific vote result."""

    if not current_user.is_contrib():
        return render_template('contrib-only.html')

    vote = get_db().get_vote(voteid)

    if not vote:
        flash('Unknown vote ID!')
        return redirect(url_for('mainpage'))

    if vote.owner.memid != current_user.memid:
        flash('You can only view results for your own votes.')
        return redirect(url_for('mainpage'))

    if not vote.is_over():
        flash('Vote must be finished to view results.')
        return redirect(url_for('mainpage'))

    # Get our list of member votes, sorted by the result cookie
    # as we can't do a sort on a method in the jinga2 template.
    membervotes = sorted(get_db().get_membervotes(vote),
                         key=lambda vote: vote.resultcookie())

    # Run the actual vote
    votesystem = SPI.CondorcetVS(vote, membervotes)
    votesystem.run()

    return render_template('vote-result.html', membervotes=membervotes,
                           vote=vote, votesystem=votesystem)


@app.route("/vote/create", methods=['GET', 'POST'])
@login_required
def create_vote():
    """Handler that creates a new vote."""

    if not current_user.is_contrib():
        return render_template('contrib-only.html')

    if not current_user.can_createvote():
        flash('You are not allowed to create new votes.')
        return redirect(url_for('mainpage'))

    form = VoteCreationForm()
    if form.validate_on_submit():
        vote = get_db().create_vote(current_user, form.title.data,
                                    form.description.data,
                                    form.start.data, form.end.data)
        return redirect(url_for('edit_vote', voteid=vote.voteid))

    return render_template('vote-create.html', form=form)


@app.route("/vote/<int:voteid>/edit", methods=['GET', 'POST'])
@login_required
def edit_vote(voteid):
    """Handler for editing a vote."""

    if not current_user.is_contrib():
        return render_template('contrib-only.html')

    vote = get_db().get_vote(voteid)

    # Do some sanity checking of our inputs.
    if not vote:
        flash('Unknown vote ID!')
        return redirect(url_for('mainpage'))

    if vote.owner.memid != current_user.memid:
        flash('You can only edit your own votes.')
        return redirect(url_for('mainpage'))

    if vote.is_active() or vote.is_over():
        flash('Vote must not have run to be edited.')
        return redirect(url_for('mainpage'))

    # Only use the submitted form to update the VoteCreation
    # details if that's what was actually submitted.
    if request.form and 'vote-btn' in request.form:
        form = VoteCreationForm(request.form, vote, prefix="vote")
    else:
        form = VoteCreationForm(None, vote, prefix="vote")

    # We always want a new voting option displayed
    newoptform = VoteOptionForm(prefix="newopt")

    # Slightly hacky, to deal with the fact we've got 4 different form
    # submission options to deal with (in the order they appear below):
    # - Delete/edit the vote itself
    # - Add new a voting option
    # - Delete the last current voting option
    # - Edit an existing voting option
    if request.form:
        if 'vote-btn' in request.form and form.validate_on_submit():
            if request.form['vote-btn'] == 'Delete':
                get_db().delete_vote(voteid)
                flash('Vote deleted.')
                return redirect(url_for('mainpage'))
            elif request.form['vote-btn'] == 'Edit':
                vote.title = form.title.data
                vote.description = form.description.data
                vote.start = form.start.data
                vote.end = form.end.data
                vote = get_db().update_vote(vote)
        elif 'obtn' in request.form and newoptform.validate_on_submit():
            if request.form['obtn'] == 'Add':
                if not newoptform.option.data:
                    flash('Must provide option text!')
                else:
                    vote = get_db().add_vote_option(vote,
                                                    newoptform.option.data,
                                                    newoptform.char.data,
                                                    newoptform.order.data)
            elif request.form['obtn'] == 'Delete':
                vote = get_db().delete_vote_option(vote.options[-1])
        else:
            for i, option in enumerate(vote.options, start=1):
                if ('obtn' + str(i) in request.form and
                        request.form['obtn' + str(i)] == 'Edit'):
                    oform = VoteOptionForm(prefix="opt" + str(i))
                    if oform.validate_on_submit():
                        if not oform.option.data:
                            flash('Must provide option text!')
                        else:
                            option.description = oform.option.data
                            option.char = oform.char.data
                            vote = get_db().update_vote_option(option)

    # Build our array of voting option forms with what the current
    # vote looks like (we may have added or removed options above,
    # so this can't be done earlier)
    oforms = []
    for i, option in enumerate(vote.options, start=1):
        oform = VoteOptionForm(prefix="opt" + str(i))
        oform.order.data = i
        if (not request.form or 'vote-btn' in request.form or
                not 'opt'+str(i)+'-char' in request.form):
            oform.option.data = option.description
            oform.char.data = option.char
        oforms.append(oform)

    # Add the new vote option form.
    if not vote.options:
        newoptform.order.data = 1
    else:
        newoptform.order.data = len(vote.options) + 1
    newoptform.char.data = chr(64 + newoptform.order.data)
    newoptform.option.data = ''
    oforms.append(newoptform)

    return render_template('vote-edit.html',
                           vote=vote, form=form,
                           oforms=oforms)


@app.route("/")
@login_required
def mainpage():
    """Handler for main page. Displays users details."""
    applications = get_db().get_applications_by_user(current_user)
    contribapp = False
    if not current_user.is_contrib():
        for apps in applications:
            if apps.contribapp and not apps.approve:
                contribapp = True

    return render_template('status.html', db=get_db(),
                           applications=applications,
                           contribapp=contribapp)


@app.route('/updateactive')
@login_required
def updateactive():
    """Update a users most recently active date and redirect to main page"""

    get_db().update_member_field(current_user.email, 'lastactive',
                                 datetime.date.today())
    return redirect(url_for('mainpage'))


@app.route('/chpass', methods=['GET', 'POST'])
@login_required
def changepw():
    """Handler for changing user password."""
    form = PWChangeForm()
    if form.validate_on_submit():
        if not current_user.validate_password(form.oldpw.data):
            flash('Invalid old password')
        elif current_user.set_password(get_db(), form.newpw.data):
            flash('Password successfully changed.')
            return redirect(url_for('mainpage'))
        else:
            flash('Error changing password.')
    return render_template('pwchange.html', form=form)


@app.route('/stats')
@login_required
def showstats():
    """Handler for showing membership statistics"""
    stats = get_db().get_stats()

    return render_template('stats.html', stats=stats)


@app.route('/verifyemail', methods=['GET', 'POST'])
@login_required
def verifyemail():
    """Handler for email verification."""
    form = EmailVerificationForm()

    verifystatus = get_db().get_verify_email(current_user)
    if not verifystatus or verifystatus['validemail']:
        flash('Email address already verified.')
        return redirect(url_for('mainpage'))

    # We want to allow this to be submitted directly via the email link
    emailkey = request.args.get('emailkey', '')

    if form.validate_on_submit():
        emailkey = form.emailkey.data

    if emailkey:
        result = get_db().verify_email(current_user, emailkey)
        if not result:
            flash('Email address verified.')
            return redirect(url_for('mainpage'))
        else:
            flash(result)

    return render_template('verifyemail.html', application=None, form=form)


@app.route('/verifyemail/resend')
@login_required
def resendverifyemail():
    """Handler to resend email verification key to a user."""

    verifystatus = get_db().get_verify_email(current_user)
    if not verifystatus or verifystatus['validemail']:
        flash('Email address already verified.')
        return redirect(url_for('mainpage'))

    # Send the email verification email
    msg = MIMEText(render_template('verify-email.txt',
                                   emailkey=verifystatus['emailkey']),
                   'plain', 'utf-8')
    msg['Subject'] = email.header.Header('SPI email verification for ' +
                                         current_user.name, 'utf-8')
    msg['From'] = 'email-check@members.spi-inc.org'
    msg['To'] = current_user.email
    try:
        smtp = smtplib.SMTP(app.config['SMTP_SERVER'])
        smtp.sendmail('email-check@members.spi-inc.org',
                      [current_user.email], msg.as_string())
        smtp.quit()
        flash('Email verification re-sent.')
    except:
        flash('Unable to send email verification.')

    return redirect(url_for('verifyemail'))


@app.route('/apply', methods=['GET', 'POST'])
def application_form():
    """Handler for non-contributing membership application."""
    form = ApplicationForm()
    if form.validate_on_submit():
        application = form.get_application()
        if application:
            login_user(application.user)
            # Send the welcome / email verification email
            msg = MIMEText(render_template('newnm-email.txt',
                                           application=application),
                           'plain', 'utf-8')
            msg['Subject'] = email.header.Header('SPI Membership application '
                                                 'for ' +
                                                 application.user.name,
                                                 'utf-8')
            msg['From'] = 'email-check@members.spi-inc.org'
            msg['To'] = application.user.email
            try:
                smtp = smtplib.SMTP(app.config['SMTP_SERVER'])
                smtp.sendmail('email-check@members.spi-inc.org',
                              [application.user.email], msg.as_string())
                smtp.quit()
            except:
                flash('Unable to send email verification.')

            # For the first user automatically upgrade them to be a
            # contributing member + manager. Helps with test installs.
            if application.appid == 1:
                get_db().update_member_field(application.user.email,
                                             'iscontrib',
                                             True)
                get_db().update_member_field(application.user.email,
                                             'ismanager',
                                             True)

            # Display the confirmation / email verification page
            form = EmailVerificationForm()
            return render_template('verifyemail.html',
                                   application=application, form=form)

    return render_template('apply.html', form=form)


@app.route('/getpass', methods=['GET', 'POST'])
def getpass():
    """Hander for issuing a password reset."""
    form = PWResetForm()
    user = None
    if form.validate_on_submit():
        user = get_db().get_member(form.email.data)
        if user:
            length = 13
            chars = string.ascii_letters + string.digits + '!@#$%^&*()'
            password = ''.join(random.choice(chars) for i in range(length))
            user.set_password(get_db(), password)

            # Send the welcome / email verification email
            msg = MIMEText(render_template('resetpw-email.txt',
                                           pw=password),
                           'plain', 'utf-8')
            msg['Subject'] = email.header.Header('SPI Password reset for ' +
                                                 user.name,
                                                 'utf-8')
            msg['From'] = 'membership@spi-inc.org'
            msg['To'] = user.email
            try:
                smtp = smtplib.SMTP(app.config['SMTP_SERVER'])
                smtp.sendmail('membership@spi-inc.org', [user.email],
                              msg.as_string())
                smtp.quit()
            except:
                flash('Unable to send password reset email.')

    return render_template('getpass.html', form=form, user=user)


@app.route('/privatesubs')
@login_required
def privatesubs():
    """Return the list of -private subscriber addressess"""

    if request.remote_addr not in app.config['LIST_HOSTS']:
        if not current_user.is_manager():
            return render_template('manager-only.html')

    emails = get_db().get_private_emails()
    emaillist = '\n'.join(emails)
    return Response(emaillist, mimetype='text/plain')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handler for user logins, redirecting if appropriate."""
    form = LoginForm()
    if form.validate_on_submit():
        user = form.get_user()
        if user is None:
            flash('Invalid login. Please try again.')
        else:
            login_user(user)
            nextpage = request.args.get('next')
            if not is_safe_url(nextpage):
                return abort(400)
            return redirect(nextpage or url_for('mainpage'))

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    """Invalidate the user's login and redirect back to the login page"""
    logout_user()
    return redirect(url_for('login'))


@app.errorhandler(404)
def not_found(error):
    """Return a suitable 404 page for unhandled URLs"""
    return render_template('404.html'), 404


if __name__ == "__main__":
    app.run()
