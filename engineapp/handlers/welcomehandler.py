import models.models as models
import handlers.bloghandler as bloghandler
import google.appengine.ext.db as db


class WelcomeHandler(bloghandler.BlogHandler):
    def get(self):
        posts = ''
        # show 10 most recent posts by all users
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
