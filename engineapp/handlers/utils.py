import webapp2
import re
from google.appengine.ext import ndb
import hmac
from secret import SECRET
import random
import string
import hashlib


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


def verify_login(f):
    '''this is a decorator checking the logged in status of the user'''
    def _wrapper(*a, **kw):
        self = a[0]
        user = getattr(self, 'user')
        if user is None:
            message = """Only a logged in user can edit or delete own posts, like others'
                    posts, or edit or delete own comments."""
            self.redirect(webapp2.uri_for('login', message=message))
        return f(*a, **kw)
    return _wrapper


def validate_post_key(f):
    '''this is a decorator checking the validity of post_key_st'''
    def _wrapper(*a, **kw):
        try:
            post_key_st = kw['post_key_st']
            post_key = ndb.Key(urlsafe=post_key_st)
            post = post_key.get()
        except:  # catch all
            post = None
        kw['post'] = post
        return f(*a, **kw)
    return _wrapper
