import webapp2

from libs.utils import *
from libs.db.post import Post
from libs.db.user import User
from google.appengine.ext import db


##### define ancestor keys for models
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

def user_key(name = 'default'):
    return db.Key.from_path('users', name)


##### blog stuff
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


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
        matched_users = User.all().filter('username =', username).get()
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
            user = User(parent = user_key(), username = username, password = make_pw_hash(username, password))
            user.put()

            # update cookies
            user_id = str(user.key().id())
            self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % make_secure_val(user_id))
            
            # redirect to welcome page
            self.redirect('/welcome')


class Login(BlogHandler):
    def get(self):
        self.render("login-form.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        # determine if this user is valid i.e. user exists and password matches
        have_error = True
        matched_users = User.all().filter('username =', username).get()
        if matched_users:
            hashed_pwd = matched_users.password
            if valid_pw(username, password, hashed_pwd):
                have_error = False

        # if no error, redirect to welcome page
        if not have_error:
            # update cookies
            user_id = str(matched_users.key().id())
            self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % make_secure_val(user_id))

            # redirect to welcome page
            self.redirect('/welcome')
        
        # if has error, ask for re-entry
        else:
            error_login = 'Invalid login'
            self.render("login-form.html", error_login=error_login)


class Logout(BlogHandler):
    def get(self):
        # clear cookies
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

        # redirect to signup page
        self.redirect('/signup')


class Welcome(BlogHandler):
    def get(self):
        user_cookie = self.request.cookies.get('user_id')
        # if the user is valid, print welcome
        if user_cookie:
            if check_secure_val(user_cookie):
                user_id = user_cookie.split('|')[0]
                key = db.Key.from_path('User', int(user_id), parent=user_key())
                user = db.get(key)
                if user:
                    self.render('welcome.html', username = user.username)
                    return

        # otherwise back to signup due to error    
        self.redirect('/signup')


