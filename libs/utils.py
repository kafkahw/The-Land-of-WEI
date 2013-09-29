import jinja2
import os
import re

import hmac
import hashlib
import random
import string

from datetime import datetime

from google.appengine.ext import db
from google.appengine.api import memcache


# define the template dir and jinja environment
cur_dir = os.path.dirname(__file__)
template_dir = os.path.join(os.path.dirname(cur_dir), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

##### define ancestor keys for models
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

def user_key(name = 'default'):
    return db.Key.from_path('users', name)


# covenient rendering templates
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


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


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


def age_set(key, val):
    save_time = datetime.utcnow()
    memcache.set(key, (val, save_time))


def age_get(key):
    r = memcache.get(key)
    if r:
        val, save_time = r
        age = (datetime.utcnow() - save_time).total_seconds()
    else:
        val, age = None, 0

    return val, age


def age_str(age):
    s = "queried %s seconds ago"
    age = int(age)
    if age == 1:
        s = s.replace("seconds", "second")
    return s % age

