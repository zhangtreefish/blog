import models.models as models
import handlers.bloghandler as bloghandler
import google.appengine.ext.db as db


class WelcomeHandler(bloghandler.BlogHandler):
    def get(self):
        posts = ''
        # if logged in, show user's own posts
        if self.user:
            posts = models.BlogPost.query_post(self.user.key)
        # otherwise show 10 most recent posts by all users
        else:
            posts = models.BlogPost.query().order(
                -models.BlogPost.postedAt).fetch(10)
        message = self.request.get('message')
        self.render(
            'welcome.html',
            message=message,
            posts=posts,
            user_id=self.user.key.id() if self.user else None,
            username=self.user.username if self.user else None
        )
