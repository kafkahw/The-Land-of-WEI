import os
import re
from string import letters

import webapp2
import jinja2
import hmac
import hashlib
import random
import string

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)

SECRET = 'imsosecret'
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class MainPage(BlogHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        visit_cookie_str = self.request.cookies.get('visits')

        if visit_cookie_str:
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)

        # if cookie is invalid, visits will be set back to 1
        visits += 1

        new_cookie_val = make_secure_val(str(visits))

        self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)
        
        if visits > 10000:
            self.write("You are the best ever!")
        else:
            self.write("You've been here %s times!" % visits)


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)



##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

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



###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


###### signup stuff
def user_key(name = 'default'):
    return db.Key.from_path('users', name)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)


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


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/rot13', Rot13),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ],
                              debug=True)
