import models.models as models
import handlers.bloghandler as bloghandler
import google.appengine.ext.db as db


class WelcomeHandler(bloghandler.BlogHandler):
    def get(self):
        # if logged in, show user's own posts
        if self.user:
            user_posts=models.BlogPost.query_post(self.user.key)
            self.render(
                'welcome.html',
                user_id=self.user.key.id(),
                username=self.user.username,
                posts=user_posts
            )
        else:
            # otherwise show 10 most recent posts by all users
            message = self.request.get('message')
            all_posts = models.BlogPost.query().order(-models.BlogPost.postedAt).fetch(10)
            self.render(
                'welcome.html',
                message=message,
                posts=all_posts
            )
