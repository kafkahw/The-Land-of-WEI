from google.appengine.ext import db
from libs.utils import render_str


class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

    def as_dict(self):
    	time_fmt = '%c'
    	d = {'subject': self.subject,
    		 'content': self.content,
    		 'created': self.created.strftime(time_fmt),
    		 'last_modified': self.last_modified.strftime(time_fmt)}
    	return d
    	