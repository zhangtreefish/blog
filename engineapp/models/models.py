from google.appengine.ext import ndb
import datetime


class User(ndb.Model):
    username = ndb.StringProperty(required=True)
    password_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()
    lastLoggedIn = ndb.DateTimeProperty(auto_now=True)

    @classmethod
    def query_user(cls, username):
        return cls.query(cls.username == username).get()

    @classmethod
    def update_lastLoggedIn(cls, user_id):
        user = cls.get_by_id(int(user_id))
        user.lastLoggedIn = datetime.datetime.now()
        user.put()


class BlogPost(ndb.Model):
    """Models a BlogPost entry with subject, content, author, and date."""
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    postedAt = ndb.DateTimeProperty(auto_now_add=True)
    author = ndb.StringProperty(required=True)
    liked_by = ndb.StringProperty(repeated=True)
    tag = ndb.StringProperty(required=True)

    @classmethod
    def query_post(cls, author_key):
        return cls.query(ancestor=author_key).order(-cls.postedAt).fetch()

    @classmethod
    def from_id(cls, post_id, author_key):
        return cls.get_by_id(int(post_id), parent=author_key)


class Comment(ndb.Model):
    comment_key_st = ndb.StringProperty(required=True)
    comment = ndb.StringProperty(required=True)
    postedAt = ndb.DateTimeProperty(auto_now_add=True)
    commenter = ndb.StringProperty(required=True)

    @classmethod
    def query_comments(cls, post_key):
        return cls.query(ancestor=post_key).order(-cls.postedAt).fetch()


