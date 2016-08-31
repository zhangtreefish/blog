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

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
# jinja2.6 deos not support lstrip_blocks
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               trim_blocks=True,
                               # lstrip_blocks=True,
                               autoescape=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)
def valid_password(password):
    return PASSWORD_RE.match(password)
def valid_email(email):
    return EMAIL_RE.match(email)

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

        # empty dict evaluates to False
        if my_kw:
            my_kw['username'] = username_input
            my_kw['email'] = email_input
            self.render('signup.html', **my_kw)

        else:
            self.redirect('/welcome?username={}'.format(username_input))

class FormHandler(webapp2.RequestHandler):
    def post(self):
        q = self.request.get("q")
        # self.response.write(q)
        # useful for debug:
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write(self.request)

# Remove debug=True before final deployment
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/fizzbuzz', FizzBuzzHandler),
    ('/rot13', Rot13Handler),
    ('/welcome', WelcomeHandler),
    ('/signup', SignUpHandler)
], debug=True)
