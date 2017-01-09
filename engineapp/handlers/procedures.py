import models.models as models
import handlers.bloghandler as bloghandler
from handlers.utils import valid_username, valid_password, valid_pw, valid_email


class UsersHandler(bloghandler.BlogHandler):
    def get(self):
        all_users = models.User.query().order(-models.User.lastLoggedIn).fetch(5)
        self.render('users.html', users=all_users)


class SignUpHandler(bloghandler.BlogHandler):
    def get(self):
        self.render('signup.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        my_kw = {}

        if username is None:
            my_kw['username_err_required'] = "A username is required."
        if valid_username(username) is None:
            my_kw['username_err_nonvalid'] = '''A username is 3-20 characters
            long and composed of a-zA-Z0-9'''
        if self.registered_username(username):
            my_kw['username_err_unique'] = '''Username {} is already
            taken.'''.format(username)

        if password is None or valid_password(password) is None:
            my_kw['password_err'] = '''Password invalid, its length has to
            be 3-20 .'''

        if verify is None or password != verify:
            my_kw['verify_err'] = "Your passwords didn't match."

        if email and valid_email(email) is None:
            my_kw['email_err'] = "That's not a valid email."

        if my_kw:
            my_kw['username'] = username
            my_kw['email'] = email
            self.render('signup.html', **my_kw)

        else:
            user_id = self.registerUser(
                username,
                password,
                email or None
            )
            self.login(user_id)


class LogInHandler(bloghandler.BlogHandler):
    def get(self, *a, **kw):
        kw['message'] = self.request.get('message')
        self.render('login.html', *a, **kw)

    def post(self):
        my_kw = {}
        username = self.request.get('username')
        password = self.request.get('password')
        user_stored = models.User.query_user(username)

        # if already logged in, go to /welcome
        if self.user and self.user.username == username:
            self.redirect('/welcome')

        # if errors, redo /login
        elif username is None:
            my_kw['username_err_required'] = "A username is required."
        elif self.registered_username(username) is None:
            my_kw['username_err_nonexistent'] = '''No registered user {} is
             found.'''.format(username)
        elif password is None or valid_password(password) is None:
            my_kw['password_err'] = "Need a valid password 3-20 Char. long."
        elif user_stored and valid_pw(
                    username, password, user_stored.password_hash) is not True:
            my_kw['login_err'] = "No such username and Password on record."
        if my_kw:
            my_kw['username'] = username
            my_kw['message'] = self.request.get('message')
            self.render('login.html', **my_kw)

        else:
            user_id = user_stored.key.id()
            models.User.update_lastLoggedIn(user_id)
            self.login(user_id)


class LogOutHandler(bloghandler.BlogHandler):
    def get(self):
        if self.user:
            self.render('logout.html', username=self.user.username)
        else:
            self.none_logged_in()

    def post(self):
        if self.user:
            self.logout()
        else:
            self.none_logged_in()
