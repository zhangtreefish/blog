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


# The following handle setting and verification for 'password' cookie
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


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)  # load template from environment
        return t.render(**params)  # render template with params

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class WelcomeHandler(Handler):
    def get(self):
        username = self.request.get("username")
        password_cookie = self.request.cookies.get(username)
        all_posts = BlogPost.query().order(-BlogPost.postedAt).fetch(5)
        if username and password_cookie:
            self.render('welcome.html', username=username, posts=all_posts)
        else:
            self.redirect('/blog/signup')


class BlogPost(ndb.Model):
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    postedAt = ndb.DateTimeProperty(auto_now_add=True)
    author = ndb.StringProperty(required=True)


class User(ndb.Model):
    username = ndb.StringProperty(required=True)
    password_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()
    lastLoggedIn = ndb.DateTimeProperty(auto_now_add=True)


def registered_username(name):
    return name if User.query(User.username==name).get() is not None else None

    # @classMethod
    # def matching_password(name, password):
    #     password_hash = make_pw_hash(name, password)


def registerUser(name, password, email=None):
    password_hash = make_pw_hash(name, password) or 'pwd hash'
    user = User(username=name, password_hash=password_hash, email=email)
    user_key = user.put()
    return user_key.id()


class BlogHandler(Handler):
    def get(self):
        # Model.all (keys_only=False)
        all_posts = BlogPost.query().order(-BlogPost.postedAt).fetch(5)
        self.render('blog_front.html', posts=all_posts)


class UsersHandler(Handler):
    def get(self):
        all_users = User.query().order(-User.lastLoggedIn).fetch(5)
        self.render('users.html', users=all_users)


class SignUpHandler(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        username_input = self.request.get('username')
        password_input = self.request.get('password')
        verify_input = self.request.get('verify')
        email_input = self.request.get('email')

        my_kw = {}

        if username_input is None:
            my_kw['username_err_required'] = "A username is required."
        if valid_username(username_input) is None:
            my_kw['username_err_nonvalid'] = '''A username is 3-20 characters
            long and composed of a-zA-Z0-9'''
        if registered_username(username_input) is not None:
            my_kw['username_err_unique'] = '''Username {} is already
            taken.'''.format(username_input)

        if password_input is None or valid_password(password_input) is None:
            my_kw['password_err'] = '''Password invalid, its length has to
            be 3-20 .'''

        if verify_input is None or password_input != verify_input:
            my_kw['verify_err'] = "Your passwords didn't match."

        if email_input and valid_email(email_input) is None:
            my_kw['email_err'] = "That's not a valid email."

        if my_kw:
            my_kw['username'] = username_input
            my_kw['email'] = email_input
            self.render('signup.html', **my_kw)

        else:
            password_cookie = self.request.cookies.get(username_input)
            new_cookie = make_pw_hash(username_input, password_input)
            if password_cookie is None:
                self.response.set_cookie(
                    username_input,
                    new_cookie,
                    path='/')
                user_id = registerUser(
                    username_input,
                    password_input,
                    email_input or None
                )
                self.redirect(
                    '/blog/welcome?username={}'.format(username_input))
            else:
                is_cookie_secure = valid_pw(
                    username_input,
                    password_input,
                    password_cookie
                )
                if is_cookie_secure is not True:
                    self.write('Entered password did not match record.')
                    self.render('signup.html')
                else:
                    user_id = registerUser(
                        username_input,
                        password_input,
                        email_input or None
                        )
                    self.redirect(
                        '/blog/welcome?user_id={}'.format(user_id)
                    )


class LogInHandler(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username_input = self.request.get('username')
        password_input = self.request.get('password')

        my_kw = {}

        if username_input is None:
            my_kw['username_err_required'] = "A username is required."
        if registered_username(username_input) is None:
            my_kw['username_err_nonexistent'] = '''No registered user {} is
             found.'''.format(username_input)

        if password_input is None or valid_password(password_input) is None:
            my_kw['password_err'] = "Need a valid password 3-20 Char. long."

        if my_kw:
            my_kw['username'] = username_input
            self.render('login.html', **my_kw)

        else:
            password_cookie = self.request.cookies.get(username_input)
            new_cookie = make_pw_hash(username_input, password_input)
            if password_cookie is None:
                self.response.set_cookie(
                    username_input,
                    new_cookie,
                    path='/')
                self.redirect(
                    '/blog/welcome?username={}'.format(username_input)
                )
            else:
                is_cookie_secure = valid_pw(
                    username_input, password_input, password_cookie)
                if is_cookie_secure is not True:
                    my_kw['password_err_nomatch'] = "Password does not match."
                    self.render('login.html', **my_kw)
                else:
                    self.redirect(
                        '/blog/welcome?username={}'.format(username_input)
                    )


class LogOutHandler(Handler):
    def get(self):
        username = self.request.get('username')
        password_cookie = self.request.cookies.get(username)
        if password_cookie is None:
            self.write('User {} is currently logged out'.format(username))
            self.redirect(
                    '/blog/welcome')
        self.render('logout.html', username=username)

    def post(self):
        # TODO: user = users.get_current_user()
        username = self.request.get('username')

        password_cookie = self.request.cookies.get(username)
        if password_cookie is None:
                self.write('User {} is currently logged out'.format(username))
        else:
            self.response.delete_cookie(username)
            # self.response.set_cookie(
            #         '',
            #         ' ',
            #         Path='/')
            # self.response.headers.add_header(
            # 'Set-Cookie', 'user_id=; Path=/')
            # r'.+=;\s*Path=/'
            # self.response.headers.add_header('Set-Cookie', 'username=; Path=/')
            self.redirect('/blog/login')


class NewPostHandler(Handler):
    def get(self):
        author = self.request.get('username')
        my_kw = {}
        if author is None:
            my_kw['author_err'] = 'Login is required in order to post'
        self.render('new_post.html', **my_kw)

    def post(self):
        author_name = self.request.get('username')
        subject = self.request.get('subject')
        content = self.request.get('content')

        my_kw = {}

        if author_name is None:
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
            author_key = User.query(User.username==author_name).get().key
            post_id = ndb.Model.allocate_ids(size=1, parent=author_key)[0]
            post_key = ndb.Key('BlogPost', post_id, parent=author_key)
            new_post = BlogPost(
                parent=author_key,
                subject=subject,
                content=content,
                author=author_name)
            self.write('str(new_post)'+str(new_post))
            new_post.put()
            new_post_key = new_post.key

            self.redirect(
                webapp2.uri_for('postpermalink', post_id=post_id, parent_id=author_key.id())
            )


class PostPermalinkHandler(Handler):
    def get(self, post_id):
        # print(self.request.route_args)
        # Model.get_by_id (ids, parent=None)
        parent_id = self.request.get('parent_id')
        parent_key = ndb.Key('User', parent_id)
        the_post_key = ndb.Key('BlogPost', post_id, parent=parent_key)
        self.write('the_post_key')
        self.write(the_post_key.urlsafe())
        the_post = the_post_key.get()
        # self.write('the_post.author'+the_post.content)
        self.render('post_permalink.html',

                    author=the_post.author,
                    subject=the_post.subject,
                    content=the_post.content,
                    postedAt=the_post.postedAt)


# Remove debug=True before final deployment
app = webapp2.WSGIApplication([
    webapp2.Route(r'/blog', handler=BlogHandler, name='blog'),
    webapp2.Route(r'/blog/welcome', handler=WelcomeHandler, name='welcome'),
    webapp2.Route(r'/blog/signup', handler=SignUpHandler, name='signup'),
    webapp2.Route(r'/blog/login', handler=LogInHandler, name='login'),
    webapp2.Route(r'/blog/logout', handler=LogOutHandler, name='logout'),
    webapp2.Route(r'/blog/newpost', handler=NewPostHandler, name='newpost'),
    webapp2.Route(r'/blog/post/<post_id>',
                  handler=PostPermalinkHandler, name='postpermalink'),
    webapp2.Route(r'/blog/users', handler=UsersHandler, name='users')
], debug=True)
