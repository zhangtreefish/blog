import webapp2
import handlers.welcomehandler as welcomehandler
import handlers.procedures as procedures
import handlers.blogging as blogging


# Remove debug=True before final deployment
app = webapp2.WSGIApplication([
    webapp2.Route(r'/', handler=welcomehandler.WelcomeHandler, name='welcome'),
    webapp2.Route(r'/welcome', handler=welcomehandler.WelcomeHandler, name='welcome'),
    webapp2.Route(r'/signup', handler=procedures.SignUpHandler, name='signup'),
    webapp2.Route(r'/login', handler=procedures.LogInHandler, name='login'),
    webapp2.Route(r'/logout', handler=procedures.LogOutHandler, name='logout'),
    webapp2.Route(r'/newpost', handler=blogging.NewPostHandler, name='newpost'),
    webapp2.Route(r'/post/<post_key_st>',
                  handler=blogging.PostPermalinkHandler, name='postpermalink'),
    webapp2.Route(r'/post/<post_key_st>/newcomment',
                  handler=blogging.NewCommentHandler, name='newcomment'),
    webapp2.Route(r'/post/<post_key_st>/comment/<comment_key_st>/edit',
                  handler=blogging.EditCommentHandler, name='editcomment'),
    webapp2.Route(r'/post/<post_key_st>/deletecomment',
                  handler=blogging.DeleteCommentHandler, name='deletecomment'),
    webapp2.Route(r'/post/<post_key_st>/edit',
                  handler=blogging.EditPostHandler, name='editpost'),
    webapp2.Route(r'/post/<post_key_st>/like',
                  handler=blogging.LikePostHandler, name='likepost'),
    webapp2.Route(r'/deletepost',
                  handler=blogging.DeletePostHandler, name='deletepost'),
    webapp2.Route(r'/users', handler=procedures.UsersHandler, name='users')
], debug=True)
