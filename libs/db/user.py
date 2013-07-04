from google.appengine.ext import db
from libs.utils import render_str, user_key
from libs.utils import make_pw_hash, valid_pw


class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
    	return User.get_by_id(uid, parent = user_key())

    @classmethod
    def by_name(cls, name):
    	u = User.all().filter('name =', name).get()
    	return u
	
	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = user_key(),
					name = name,
					password = pw_hash,
					email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.password):
			return u

