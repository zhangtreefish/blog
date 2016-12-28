#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import jinja2
import codecs
import re
import datetime
from google.appengine.ext import ndb
import hmac
from secret import SECRET
import random
import string
import hashlib
from google.appengine.api import users


# Implement the hashing of user_id to be used in cookie
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


# The following handles setting and verification for password hashing
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    if salt is None:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    li = h.split(',')
    sal = li[-1]
    return True if h == make_pw_hash(name, pw, sal) else False


USER_RE = re.compile(r"^[\w-]{3,20}$")  # \w same as a-zA-Z0-9_
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_username(username):
    return USER_RE.match(username)


def valid_password(password):
    return PASSWORD_RE.match(password)


def valid_email(email):
    return EMAIL_RE.match(email)

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
# jinja2.6 deos not support lstrip_blocks
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               trim_blocks=True,
                               # lstrip_blocks=True,
                               autoescape=True)


class BlogPost(ndb.Model):
    """Models a BlogPost entry with subject, content, author, and date."""
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    postedAt = ndb.DateTimeProperty(auto_now_add=True)
    author = ndb.StringProperty(required=True)

    @classmethod
    def query_post(cls, user_key):
        return cls.query(ancestor=user_key).order(-cls.postedAt)


class User(ndb.Model):
    username = ndb.StringProperty(required=True)
    password_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()
    lastLoggedIn = ndb.DateTimeProperty(auto_now_add=True)

    @classmethod
    def query_user(cls, username):
        return cls.query(cls.username==username).get()


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)  # load template from environment
        return t.render(**params)  # render template with params

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def get_secure_cookie_val(self, cookie_name):
        cookie_val = self.request.cookies.get(cookie_name)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id = self.get_secure_cookie_val("user_id")
        self.user = user_id and User.get_by_id(int(user_id))

    def registered_username(self, username):
        """verify if a username is still available for use"""
        return username if User.query(User.username==username).get() else None

        # @classMethod
        # def matching_password(name, password):
        #     password_hash = make_pw_hash(name, password)

    def registerUser(self, name, password, email=None):
        password_hash = make_pw_hash(name, password) or 'pwd hash'
        user_id = ndb.Model.allocate_ids(size=1)[0]
        user = User(username=name, password_hash=password_hash, email=email, id=user_id)
        user_key = user.put()
        return user_id

    def setSecureCookie(self, user_id):
        """
        Use cookie to establish log in session
        TODO: implement one-time-use cookie in lieu of persistent cookie
        """
        user_cookie = make_secure_val(str(user_id))
        self.response.set_cookie(
                'user_id',
                user_cookie,
                path='/')

    def login(self, user_id):
        self.setSecureCookie(user_id)
        self.redirect('/blog/welcome')

    def logout(self):
        self.response.delete_cookie('user_id')
        self.redirect('/blog/welcome')


class WelcomeHandler(Handler):
    def get(self):
        if self.user:
            all_posts = BlogPost.query().order(-BlogPost.postedAt).fetch(10)
            self.render(
                'welcome.html',
                user_id=self.user.key.id(),
                username=self.user.username,
                posts=all_posts
            )
        else:
            self.render('welcome.html')


# class BlogHandler(Handler):
#     def get(self):
#         # Model.all (keys_only=False)
#         all_posts = BlogPost.query().order(-BlogPost.postedAt).fetch(5)
#         self.render('blog_front.html', posts=all_posts)


class UsersHandler(Handler):
    def get(self):
        all_users = User.query().order(-User.lastLoggedIn).fetch(5)
        self.render('users.html', users=all_users)


class SignUpHandler(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        my_kw = {}

        if username is None:
            my_kw['username_err_required'] = "A username is required."
        if valid_username(username) is None:
            my_kw['username_err_nonvalid'] = '''A username is 3-20 characters
            long and composed of a-zA-Z0-9'''
        if registered_username(username):
            my_kw['username_err_unique'] = '''Username {} is already
            taken.'''.format(username)

        if password is None or valid_password(password) is None:
            my_kw['password_err'] = '''Password invalid, its length has to
            be 3-20 .'''

        if verify is None or password != verify:
            my_kw['verify_err'] = "Your passwords didn't match."

        if email and valid_email(email) is None:
            my_kw['email_err'] = "That's not a valid email."

        if my_kw:
            my_kw['username'] = username
            my_kw['email'] = email
            self.render('signup.html', **my_kw)

        else:
            user_id = self.registerUser(
                username,
                password,
                email or None
            )
            self.login(user_id)


class LogInHandler(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        user = User.query_user(username)

        my_kw = {}

        if self.user:
            my_kw['user_in_session'] = "user already logged in"
            self.redirect('/blog/welcome')

        if username is None:
            my_kw['username_err_required'] = "A username is required."
        if self.registered_username(username) is None:
            my_kw['username_err_nonexistent'] = '''No registered user {} is
             found.'''.format(username)
        if password is None or valid_password(password) is None:
            my_kw['password_err'] = "Need a valid password 3-20 Char. long."

        if valid_pw(
                    username, password, user.password_hash) is not True:
            my_kw['password_err_nomatch'] = "Password does not match cookie."

        if my_kw:
            my_kw['username'] = username
            self.render('login.html', **my_kw)

        else:
            self.login(user.key.id())


class LogOutHandler(Handler):
    def get(self):
        username = self.user.username or None
        self.render('logout.html', username=username)

    def post(self):
        if self.user is None:
            self.write('No one is currently logged in')
        else:
            self.logout()


class NewPostHandler(Handler):
    def get(self):
        my_kw = {}
        my_kw['author_id'] = self.request.get('user_id')
        if my_kw['author_id'] is None:
            my_kw['author_err'] = 'Login is required in order to post'
        self.render('new_post.html', **my_kw)

    def post(self):
        author_id = self.request.get('user_id')
        subject = self.request.get('subject')
        content = self.request.get('content')

        my_kw = {}

        if author_id is None:
            my_kw['author_err'] = 'Login is required in order to post'
        if subject is None:
            my_kw['subject_err'] = 'Subject is a required field for blogs'
        if content is None:
            my_kw['content_err'] = 'Content is a required field for blogs'

        if my_kw:
            my_kw['subject'] = subject
            my_kw['content'] = content
            self.render('new_post.html', **my_kw)

        else:
            my_kw['subject'] = subject
            my_kw['content'] = content
            author = User.get_by_id(int(author_id))
            author_key = author.key
            post_id = ndb.Model.allocate_ids(size=1, parent=author_key)[0]
            post_key = ndb.Key('BlogPost', post_id, parent=author_key)
            new_post = BlogPost(
                id=post_id,
                parent=author_key,
                subject=subject,
                content=content,
                author=author.username)
            new_post.put()
            self.redirect(
                webapp2.uri_for('postpermalink', post_id=post_id, author_key_string=author_key.urlsafe())
            )


class PostPermalinkHandler(Handler):
    def get(self, post_id):
        author_key_string = self.request.get('author_key_string')
        author_key = ndb.Key(urlsafe=author_key_string)
        the_post = BlogPost.get_by_id(int(post_id), parent=author_key)
        self.render('post_permalink.html',
                    author=the_post.author,
                    subject=the_post.subject,
                    content=the_post.content,
                    postedAt=the_post.postedAt,
                    author_key_string=author_key_string,
                    author_id=author_key.id())


# Remove debug=True before final deployment
app = webapp2.WSGIApplication([
    webapp2.Route(r'/blog/welcome', handler=WelcomeHandler, name='welcome'),
    webapp2.Route(r'/blog/signup', handler=SignUpHandler, name='signup'),
    webapp2.Route(r'/blog/login', handler=LogInHandler, name='login'),
    webapp2.Route(r'/blog/logout', handler=LogOutHandler, name='logout'),
    webapp2.Route(r'/blog/newpost', handler=NewPostHandler, name='newpost'),
    webapp2.Route(r'/blog/post/<post_id>',
                  handler=PostPermalinkHandler, name='postpermalink'),
    webapp2.Route(r'/blog/users', handler=UsersHandler, name='users')
], debug=True)
