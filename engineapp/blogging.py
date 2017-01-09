from models import User, BlogPost, Comment
from bloghandler import BlogHandler
from utils import verify_login, validate_post_key
from google.appengine.ext import ndb
from google.appengine.ext.db import Error


class NewPostHandler(BlogHandler):
    @verify_login
    def get(self):
        self.render('new_post.html', author_id=self.user.key.id())

    @verify_login
    def post(self):
        author = self.user
        subject = self.request.get('subject') or None
        content = self.request.get('content') or None

        my_kw = {}

        if author is None:
            my_kw['author_err'] = 'Login is required in order to post'
        if subject is None:
            my_kw['subject_err'] = 'Subject is a required field for blogs'
        if content is None:
            my_kw['content_err'] = 'Content is a required field for blogs'

        if my_kw:
            my_kw['subject'] = subject
            my_kw['content'] = content
            my_kw['author_id'] = author.key.id()
            self.render('new_post.html', **my_kw)

        else:
            my_kw['subject'] = subject
            my_kw['content'] = content
            post_id = ndb.Model.allocate_ids(size=1)[0]
            post_key = ndb.Key('BlogPost', post_id, parent=author.key)
            new_post = BlogPost(
                id=post_id,
                subject=subject,
                content=content,
                author=author.username,
                parent=author.key)
            new_post.put()
            self.go_to_post(post_key.urlsafe())


class PostPermalinkHandler(BlogHandler):
    @validate_post_key
    def get(self, post_key_st, **kw):
        post = kw['post']
        if post:
            message = self.request.get('message')
            comments = Comment.query_comments(post.key)
            self.render('post_permalink.html',
                        message=message,
                        author=post.author,
                        subject=post.subject,
                        content=post.content,
                        postedAt=post.postedAt,
                        likes=len(post.liked_by),
                        post_key_st=post_key_st,
                        comments=comments)
        else:
            self.when_no_post_key('No such post exists.')


class NewCommentHandler(BlogHandler):
    @verify_login
    @validate_post_key
    def get(self, post_key_st, **kw):
        post = kw['post']
        if post:
            self.render('new_comment.html',
                        post_key_st=post_key_st,
                        post_id=post.key.id())
        else:
            self.when_no_post_key('No such post exists.')


    @verify_login
    @validate_post_key
    def post(self, post_key_st, **kw):
        post = kw['post']
        if post:
            comment = self.request.get('newcomment')
            comment_id = ndb.Model.allocate_ids(size=1)[0]
            comment_key = ndb.Key('Comment', comment_id, parent=post.key)
            new_comment = Comment(
                id=comment_id,
                comment=comment,
                commenter=self.user.username,
                comment_key_st=comment_key.urlsafe(),
                parent=post.key)
            new_comment.put()
            self.go_to_post(post_key_st)
        else:
            self.when_no_post_key('No such post available for comment.')


class EditCommentHandler(BlogHandler):
    @verify_login
    @validate_post_key
    def post(self, post_key_st, comment_key_st, **kw):
        try:
            post = kw['post']
            if post and comment_key_st:
                comment_key = ndb.Key(urlsafe=comment_key_st)
                comment = comment_key.get()
                editor_name = self.user.username
                comment_author_name = comment.commenter
                message = ''
                if editor_name == comment_author_name:
                    comment.comment = self.request.get('comment')
                    comment.put()
                    message = 'Comment successfully edited!'
                else:
                    message = "Can not edit others' comment"
                self.go_to_post(post_key_st, message)
            else:
                self.when_no_post_key('No such post or comment available')
        except Error as err:
            print("Error: {0}".format(err))


class DeleteCommentHandler(BlogHandler):
    @verify_login
    @validate_post_key
    def post(self, post_key_st, **kw):
        try:
            post = kw['post']
            if post:
                deleter_name = self.user.username
                comment_key_st = self.request.get('comment_key_st')
                comment_key = ndb.Key(urlsafe=comment_key_st)
                comment = comment_key.get()
                comment_author_name = comment.commenter
                message = ''
                if deleter_name == comment_author_name:
                    comment_key.delete()
                    message = 'Comment successfully deleted!'
                else:
                    message = "Can not delete others' comment"
                self.go_to_post(post_key_st, message)
            else:
                self.when_no_post_key('No such post with comment to be deleted')
        except Error as err:
            print("Error: {0}".format(err))


class EditPostHandler(BlogHandler):
    @verify_login
    @validate_post_key
    def get(self, post_key_st, **kw):
        try:
            post = kw['post']
            if post:
                editor_name = self.user.username
                author_key = post.key.parent()
                author = author_key.get()
                message = ''
                comments = Comment.query_comments(post.key)
                if len(comments) != 0:
                    self.when_commented(post_key_st)
                elif editor_name != author.username:
                    message = 'Can only edit own post'
                    self.go_to_post(post_key_st, message)
                else:
                    self.render('post_edit.html',
                                post_key_st=post_key_st,
                                subject=post.subject,
                                content=post.content)
            else:
                self.when_no_post_key('No such post')
        except Error as err:
            print("Error: {0}".format(err))

    @verify_login
    @validate_post_key
    def post(self, post_key_st, **kw):
        try:
            post = kw['post']
            if post:
                editor_name = self.user.username
                author_key = post.key.parent()
                author = author_key.get()
                comments = Comment.query_comments(post.key)
                message = ''
                if len(comments) == 0 and editor_name == author.username:
                    post.subject = self.request.get('subject')
                    post.content = self.request.get('content')
                    post.put()
                    message = 'Post successfully edited!'
                else:
                    message = '''Can not edit either because post
                    is already commented or that you did not author the post'''
                self.go_to_post(post_key_st, message)
            else:
                self.when_no_post_key('No such post to be edited')
        except Error as err:
            print("Error: {0}".format(err))

    def when_commented(self, post_key_st):
        message = 'Can not edit a commented post. Respond with `Comment`'
        self.go_to_post(post_key_st, message)


class LikePostHandler(BlogHandler):
    @verify_login
    @validate_post_key
    def post(self, post_key_st, **kw):
        if self.user:
            post = kw['post']
            if post:
                liker_name = self.user.username
                author_key = post.key.parent()
                author = author_key.get()
                message = ''
                # can only like others' post
                if liker_name != author.username:
                    # can only like a post once
                    if liker_name in post.liked_by:
                        message = 'You have given your one like'
                    else:
                        post.liked_by.append(liker_name)
                        post.put()
                        message = 'Thank you for liking!'
                else:
                    message = 'Can not like own post'
                self.go_to_post(post_key_st, message)
            else:
                self.when_no_post_key('No such post to be liked')
        else:
            self.when_not_authorized()


class DeletePostHandler(BlogHandler):
    @verify_login
    def get(self):
        if self.user:
            post_key_st = self.request.get('post_key_st')
            if post_key_st:
                post_key = ndb.Key(urlsafe=post_key_st)
                deleter_name = self.user.username
                author_key = post_key.parent()
                author = author_key.get()
                comments = Comment.query_comments(post_key)
                message = ''
                if len(comments) == 0 and deleter_name == author.username:
                    post = post_key.get()
                    self.render(
                        'post_delete.html',
                        username=deleter_name,
                        subject=post.subject,
                        post_key_st=post_key_st
                    )
                else:
                    self.can_not_delete(post_key_st)
            else:
                self.when_no_post_key('No such post to be deleted')
        else:
            self.when_not_authorized()

    @verify_login
    def post(self):
        try:
            if self.user:
                post_key_st = self.request.get('post_key_st')
                if post_key_st:
                    post_key = ndb.Key(urlsafe=post_key_st)
                    deleter_name = self.user.username
                    author_key = post_key.parent()
                    author = author_key.get()
                    comments = Comment.query_comments(post_key)
                    message = ''
                    if len(comments) == 0 and deleter_name == author.username:
                        post = post_key.get()
                        post.key.delete()
                        self.redirect('/welcome')
                    else:
                        self.can_not_delete(post_key_st)
                else:
                    self.when_no_post_key('No such post to be deleted')
            else:
                self.when_not_authorized()
        except Error as err:
            print("Error: {0}".format(err))

    def can_not_delete(self, post_key_st):
        message = '''Can not delete either because post
                    is already commented or that you did not author the post'''
        self.go_to_post(post_key_st, message)
