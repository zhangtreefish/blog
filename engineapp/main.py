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
from google.appengine.ext import db

import hmac
from secret import SECRET

import random
import string
import hashlib


# The following handle setting and verification for 'password' cookie
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if salt == None:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    li = h.split(',')
    sal = li[-1]
    hash = li[0]
    return True if hash==make_pw_hash(name, pw, sal).split(',')[0] else False

# The following handle setting and verification for 'visits' cookie
def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "{},{}".format(s, hash_str(s))

def check_secure_val(h):
    pos = h.find(",")
    if pos != -1:
        s = h[:pos]
        hsh = h[pos+1:]
        return s if hash_str(s)==hsh else None
    else:
        return None


USER_RE = re.compile(r"^[\w-]{3,20}$") #\w same as a-zA-Z0-9_
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
        t = jinja_env.get_template(template) #load template from environment
        return t.render(**params) # render template with params

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class MainPage(Handler):
    def get(self):
        visits = 0
        cookie_val = self.request.cookies.get("visits")
        if cookie_val:
            secure_cookie = check_secure_val(cookie_val)
            if secure_cookie and secure_cookie.isdigit():
                visits = int(secure_cookie)

        visits += 1
        new_cookie = make_secure_val("{}".format(visits))
        self.response.set_cookie("visits", "{}".format(new_cookie))

        if visits >1000:
            self.write("You are a loyal visitor!")
        else:
            self.write("You have visited {} times".format(visits))

        foods = self.request.get_all("food")
        self.render('shopping_list.html', foods=foods)

class FizzBuzzHandler(Handler):
    def get(self):
        n = self.request.get("n")
        n = n and int(n)
        self.render('fizzbuzz.html', n=n)

class Rot13Handler(Handler):
    def get(self):
        self.render('rot13.html')

    def post(self):
        msg = self.request.get('text')
        rotted_msg = codecs.encode(msg, 'rot13')
        self.render('rot13.html', text=rotted_msg)

class WelcomeHandler(Handler):
    def get(self):
        username = self.request.get("username")
        if username:
            self.render('welcome.html', username=username)
        else:
            self.redirect('/signup')

class FormHandler(webapp2.RequestHandler):
    def post(self):
        q = self.request.get("q")
        # self.response.write(q)
        # useful for debug:
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write(self.request)

# ---------Blog project--------------------------
class BlogPost(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    postedAt = db.DateTimeProperty(auto_now_add=True)

class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=True)
    lastLoggedIn = db.DateTimeProperty(auto_now_add=True)

def registerUser(name, password, email):
    user = User(username=name, password=password, email=email)
    user.put()

class BlogHandler(Handler):
    def get(self):
        all_posts = BlogPost.all().order('-postedAt').run(limit=5)  # Model.all (keys_only=False)
        self.render('blog_front.html', posts=all_posts)

class UsersHandler(Handler):
    def get(self):
        all_users = User.all().order('-lastLoggedIn').run(limit=5)
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

        if username_input is None or valid_username(username_input) is None:
            my_kw['username_err'] = "That's not a valid username."

        if password_input is None or valid_password(password_input) is None:
            my_kw['password_err'] = "That's not a valid password."

        if verify_input is None or password_input != verify_input:
            my_kw['verify_err'] = "Your passwords didn't match."

        if email_input and valid_email(email_input) is None:
            my_kw['email_err'] = "That's not a valid email."

        if my_kw:
            my_kw['username'] = username_input
            my_kw['email'] = email_input
            self.render('signup.html', **my_kw)

        else:
            password_cookie = self.request.cookies.get("password")

            if password_cookie is None:
                new_cookie = make_pw_hash("password", password_input)
                self.response.set_cookie(
                    "password",
                    new_cookie,
                    expires=(datetime.datetime.now() + datetime.timedelta(weeks=4)).strftime('%a, %d %b %Y %H:%M:%S GMT') ,
                    path='/')
                registerUser(username_input, password_input, email_input)
                self.redirect('/welcome?username={}'.format(username_input))
            else:
                is_cookie_secure = valid_pw("password", password_input, password_cookie)
                if is_cookie_secure != True:
                    self.write('Entered password did not match record.')
                    self.render('signup.html')
                else:
                    registerUser(username_input, password_input, email_input)
                    self.redirect('/welcome?username={}'.format(username_input))

class NewPostHandler(Handler):
    def get(self):
        self.render('new_post.html')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        my_kw = {}

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
            new_post = BlogPost(subject=subject, content=content)
            print(str(new_post))
            new_post.put()
            new_post_id = new_post.key().id()
            self.redirect(webapp2.uri_for('postpermalink', post_id=new_post_id))

class PostPermalinkHandler(Handler):
    def get(self, post_id):
        # print(self.request.route_args)
        the_post = BlogPost.get_by_id(int(post_id)) # Model.get_by_id (ids, parent=None)
        self.render('post_permalink.html',
                    id=post_id,
                    subject=the_post.subject,
                    content=the_post.content,
                    postedAt=the_post.postedAt)


# Remove debug=True before final deployment
app = webapp2.WSGIApplication([
    webapp2.Route(r'/', handler=MainPage, name='main'),
    webapp2.Route(r'/fizzbuzz', handler=FizzBuzzHandler, name='fizz'),
    webapp2.Route(r'/rot13', handler=Rot13Handler, name='rot13'),
    webapp2.Route(r'/welcome', handler=WelcomeHandler, name='welcome'),
    webapp2.Route(r'/blog/signup', handler=SignUpHandler, name='signup'),
    webapp2.Route(r'/blog', handler=BlogHandler, name='blog'),
    webapp2.Route(r'/blog/newpost', handler=NewPostHandler, name='newpost'),
    webapp2.Route(r'/blog/post/<post_id>', handler=PostPermalinkHandler, name='postpermalink'),
    webapp2.Route(r'/blog/users', handler=UsersHandler, name='users')
], debug=True)
