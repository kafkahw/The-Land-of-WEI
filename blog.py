import webapp2

from libs.utils import *
from libs.db.post import Post
from libs.db.user import User
from google.appengine.ext import db


##### blog stuff
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        # set user_id cookie
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        # clear user_id cookie
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts = posts)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)


class NewPost(BlogHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        # check if user already exists
        matched_users = User.by_name(username)
        if matched_users:
            params['error_username'] = "That user already exists."
            have_error = True

        # validate password
        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        # validate email
        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        # re-display signup form if having error
        if have_error:
            self.render('signup-form.html', **params)
        else:
            # add new user into database
            user = User.register(username, password, email)
            user.put()

            # new user login (update user cookie)
            self.login(user)
            
            # redirect to welcome page
            self.redirect('/welcome')


class Login(BlogHandler):
    def get(self):
        self.render("login-form.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        
        # check login info against database
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            error_login = 'Invalid login'
            self.render("login-form.html", error_login=error_login)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/signup')


class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.username)
        else:
            self.redirect('/signup')    


