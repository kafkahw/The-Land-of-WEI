import webapp2
import json

from libs.utils import *
from libs.db.post import Post
from libs.db.user import User

from google.appengine.ext import db
from google.appengine.api import memcache


##### blog stuff

MC_BLOG_KEY = 'BLOGS'       # memcache key for front page
FRONT_PAGE_LENTH = 10       # number of posts in front page

class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, obj):
        json_txt = json.dumps(obj)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

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

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'


class BlogFront(BlogHandler):
    def get(self):
        posts, age = get_posts()
        if self.format == 'html':
            if self.user:
                self.render('front-with-login.html', 
                            posts = posts,
                            age = age_str(age),
                            username = self.user.username)
            else:
                self.render('front.html', 
                            posts = posts, 
                            age = age_str(age))
        else:
            return self.render_json([p.as_dict() for p in posts])

class PostPage(BlogHandler):
    def get(self, post_id):
        # memcache key for a particular post
        post_key = 'POST_' + post_id

        # retrieve post from memcache first
        post, age = age_get(post_key)

        # if not in memcache, grab it from database
        if not post:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            # if not in database, throw errors
            if not post:
                self.error(404)
                return

            # otherwise, update memcache with post
            age_set(post_key, post)
            age = 0

        if self.format == 'html':
            if self.user:
                self.render('permalink-with-login.html',
                            post = post,
                            age = age_str(age),
                            username = self.user.username)
            else:
                self.render('permalink.html', 
                            post = post, 
                            age = age_str(age))
        else:
            self.render_json(post.as_dict())


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html", username=self.user.username)
        else:
            self.redirect('/blog/login')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            add_post(p)
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, 
                                        content=content, 
                                        error=error,
                                        username=self.user.username)


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
            self.redirect('/blog')


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
            self.redirect('/blog')
        else:
            error_login = 'Invalid login'
            self.render("login-form.html", error_login=error_login)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.username)
        else:
            self.redirect('/blog/signup')


class FlushMemcache(BlogHandler):
    """
        Flushing all caches in memcache
    """
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')


def add_post(post):
    # add post to database
    post.put()

    # get current posts in cached posts
    posts, age = age_get(MC_BLOG_KEY)

    # pop out the last one if we already have enough elements
    if len(posts) == FRONT_PAGE_LENTH:
        posts.pop()

    # insert new post at the front of posts list
    posts.insert(0, post)

    # update memcache
    age_set(MC_BLOG_KEY, posts)

    return str(post.key().id())


def get_posts():

    # look into memcache first
    posts, age = age_get(MC_BLOG_KEY)

    # if not in memcache
    if posts is None:
        q = Post.all().order('-created').fetch(limit = FRONT_PAGE_LENTH)
        posts = list(q)
        age_set(MC_BLOG_KEY, posts)
        age = 0

    return posts, age
