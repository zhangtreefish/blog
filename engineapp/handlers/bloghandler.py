import os
import webapp2
import jinja2
from google.appengine.ext import ndb
from google.appengine.ext.db import Error, BadArgumentError
from google.net.proto.ProtocolBuffer import ProtocolBufferDecodeError
from handlers.utils import hash_str, make_secure_val, check_secure_val
from handlers.utils import make_salt, make_pw_hash, valid_pw
from models.models import User, BlogPost, Comment


template_dir = os.path.join(os.path.dirname(__file__), '../templates')
# jinja2.6 deos not support lstrip_blocks
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               trim_blocks=True,
                               # lstrip_blocks=True,
                               autoescape=True)

import webapp2
from functools import wraps
# def verify_login(f):
#     @wraps(f)
#     def _wrapper(self, *args, **kw):
#         # user = getattr(self, 'user')
#         user = self.user
#         if user is None:
#             message = """Only a logged in user can edit or delete own posts, like others'
#                     posts, or edit or delete own comments."""
#             self.redirect(webapp2.uri_for('login', message=message))
#         return f(self, *args, **kw)
#     return _wrapper

class BlogHandler(webapp2.RequestHandler):
    '''this is the base handler for the blog application'''
    def __init__(self, request, response):
        # Set self.request, self.response and self.app.
        self.initialize(request, response)

        # ... add your custom initializations here ...
        user_id = self.get_secure_cookie_val("user_id")
        self.user = user_id and User.get_by_id(int(user_id))

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

    # def initialize(self, *a, **kw):
    #     webapp2.RequestHandler.initialize(self, *a, **kw)
    #     user_id = self.get_secure_cookie_val("user_id")
    #     self.user = user_id and User.get_by_id(int(user_id))

    def registered_username(self, uname):
        """verify if a username is still available for use"""
        return uname if User.query(User.username == uname).get() else None

    def registerUser(self, name, password, email=None):
        password_hash = make_pw_hash(name, password) or 'pwd hash'
        user_id = ndb.Model.allocate_ids(size=1)[0]
        user = User(username=name,
                    password_hash=password_hash, email=email, id=user_id)
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
        User.update_lastLoggedIn(user_id)
        self.redirect('/welcome')

    def logout(self):
        self.response.delete_cookie('user_id')
        self.redirect('/welcome')

    def none_logged_in(self):
        '''for messaging during logout'''
        message = 'No one is currently logged in'
        self.redirect(webapp2.uri_for('login', message=message))

    def when_not_authorized(self):
        ''' handles the scenario when the user is not logged in while
        attempting to post or comment
        '''
        message = """Only a logged in user can edit or delete own posts, like others'
        posts, or edit or delete own comments."""
        self.redirect(webapp2.uri_for('login', message=message))

    def when_no_post_key(self, message=''):
        self.redirect(webapp2.uri_for('welcome', message=message))

    def go_to_post(self, post_key_st, message=''):
        '''Given a post's key str, redirected to that post's page'''
        self.redirect(
            webapp2.uri_for('postpermalink',
                            post_key_st=post_key_st, message=message)
        )

    def verified_post(self, post_key_st):
        '''a method to check if a post_key_st has a corresponding post
        and returns the post or None'''
        try:
            post_key = ndb.Key(urlsafe=post_key_st)
            post = post_key.get()
        except (ProtocolBufferDecodeError, TypeError) as err:
            self.write("ProtocolBufferDecodeError or TypeError {0}".format(err))
            self.write('Post key is required to display a post or a comment')
            post = None
        except:  # catch all
            post = None
        return post
