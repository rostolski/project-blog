import os
import re
import random
import hashlib
import hmac
from string import letters
import secure

import webapp2
import jinja2


from google.appengine.ext import db
from google.appengine.ext.db import metadata


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    val = secure.secure_val(val)
    return val

def check_user(createdby):
    current_user = self.read_secure_cookie('user_id')
    if current_user == createdby:
        return True
    else:
        return False

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
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
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

class MainPage(BlogHandler):
  def get(self):
      self.render('index.html')


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    # Defining the blog key for the site
    return db.Key.from_path('blogs', name)

def post_key(post_id):
    # Defines each post
    return db.Key.from_path('Post', int(post_id), parent=blog_key())

def like_dup(ent, login_id, post_id):
    key = post_key(post_id)
    like_exists = db.GqlQuery("SELECT * "
                              "FROM " + ent +
                              " WHERE like_user_id = '" + login_id +
                              "' AND ANCESTOR IS :1", key).get()
    return like_exists

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    createdby = db.StringProperty(required = True)

    def render_post(self, login_id, post_id):
        likes = self.post_likes(post_id)
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", login_id = User.name, likes = likes, p = self)

    def post_likes(self, post_id):
        # gets the metadata about the datastor
        kinds = metadata.get_kinds()
        # checks to see if any likes exist and if so displays them
        if u'PostLike' in kinds:
            likes = db.GqlQuery("SELECT * "
                                "FROM PostLike "
                                "WHERE ANCESTOR IS :1",
                                post_key(post_id)).count()
        else:
            likes = 0
        return likes

    def post_like_dup(self, login_id, post_id):
        exists = like_dup('PostLike', login_id, post_id)
        return exists

class Comments(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    createdby = db.StringProperty(required = True)

    def render_comment(self, login_id, post_id):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", login_id = login_id, comment = self)

class PostLike(db.Model):
    # hanldes likes for each of the posts
    like_user_id = db.StringProperty(required=True)

class BlogFront(BlogHandler):
    # Loads all blog posts
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)

class LoadPost(BlogHandler):
    # Loads individual blog postings with their comments
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            comments = db.GqlQuery("SELECT * "
                                "FROM Comments "
                                "WHERE ANCESTOR IS :1", key)
            if not post:
                self.error(404)
                return
            self.render("permalink.html", post=post, comments=comments)

        else:
            self.redirect("/login")
    #Takes information from the single blog posting load and determines what action the user took
    def post(self, post_id):
        edit_post_id = self.request.get('edit_post_id')
        comment_post_id = self.request.get('comment_post_id')
        like_post_id = self.request.get('like_post_id')
        user_name = self.request.get('user_name')
        edit_comment_id = self.request.get('edit_comment_id')

        if edit_post_id:
            #Edit post
            self.redirect('/blog/editpost?post_id='+ post_id)
        if comment_post_id:
            #New Comment
            self.redirect('/blog/newcomment?post_id='+ post_id)
        if like_post_id:
            #User liked the post
                post_id = like_post_id
                user_id = self.read_secure_cookie('user_id')
                if not like_dup('PostLike', user_id, post_id):
                    like = PostLike(like_user_id=user_name,
                                    parent=post_key(post_id))
                    like.put()
                    self.redirect('/blog')
        if edit_comment_id:
            #Edit the comment
            self.redirect('/blog/editcomment?comment_id=%s&post_id=%s' % (edit_comment_id, post_id))

class LoadComment(BlogHandler):
    def get(self, comment_id):
        #Loading comments
        post_id = self.request.get('post_id')
        key = db.Key.from_path('Comments', int(comment_id), parent=post_key(post_id))
        comment = db.get(key)

        if not comment:
            self.error(404)
            return

        self.render("commentlink.html", comment = comment)

class NewPost(BlogHandler):
    # Loading form to create a new blog post
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        # Taking in the information from the completed form to create a new blog post
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        createdby = self.user.name

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, createdby = createdby)
            p.put()
            self.redirect('/blog/post/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class NewComment(BlogHandler):
    def get(self):
        # Loading the form to create a new comment
        if self.user:
            self.render("newcomment.html")
        else:
            self.redirect("/login")

    def post(self):
        # Taking the content from the form to create an entry in the DB for the comment
        if not self.user:
            self.redirect('/blog')

        post_id = self.request.get('post_id')
        subject = self.request.get('subject')
        content = self.request.get('content')
        createdby = self.user.name

        if subject and content:
            comment = Comments(parent = post_key(post_id), subject = subject, content = content, createdby = createdby)
            comment.put()
            comment_id = str(comment.key().id())
            self.redirect('/blog/comment/%s?post_id=%s' % (comment_id, post_id))
        else:
            error = "subject and content, please!"
            self.render("newcomment.html", post_id = post_id, subject=subject, content=content, error=error)

class EditPost(BlogHandler):
    def get(self):
        #Loading existing post conent into the form to allow it to be edited
        post_id = self.request.get('post_id')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("editpost.html", post = post)

    def post(self):
        # If the post was edited, updates the DB
        if not self.user:
            self.redirect('/blog')

        post_id = self.request.get('post_id')
        subject = self.request.get('subject')
        content = self.request.get('content')
        post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        if subject and content:
            post = db.get(post_key)
            post.subject = subject
            post.content = content
            post.put()

            post_id = str(post.key().id())
            self.redirect('/blog/post/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render("editpost.html", subject=subject, content=content, error=error)

class EditComment(BlogHandler):
    def get(self):
        # Loads the comment form to prep for an update
        user_id = self.read_secure_cookie('user_id')
        comment_id = self.request.get('comment_id')
        post_id = self.request.get('post_id')
        key = db.Key.from_path('Comments', int(comment_id), parent=post_key(post_id))
        comment = db.get(key)

        if not comment:
            self.error(404)
            return

        self.render("editcomment.html", comment = comment, post_id = post_id, user_id = user_id)

    def post(self):
        # Updates the DB with any changes made
        if not self.user:
            self.redirect('/blog')
        # Takes the data from the editcomment.html form and makes connection to the DB
        post_id = self.request.get('post_id')
        comment_id = self.request.get('comment_id')
        subject = self.request.get('subject')
        content = self.request.get('content')
        comment_key = db.Key.from_path('Comments', int(comment_id), parent=post_key(post_id))

        # Loads the date from the form into the DB
        if subject and content:
            comment = db.get(comment_key)
            comment.subject = subject
            comment.content = content
            comment.put()

            self.redirect('/blog/comment/%s?post_id=%s' % (comment_id, post_id))
        else:
            error = "subject and content, please!"
            self.render("editcomment.html", subject=subject, content=content, error=error, comment_id=comment_id, post_id=post_id)

class DeletePost(BlogHandler):
    # This deletes blog posts - bug: comments of deleted post still in DB, just not shown on screen anymore
    def post(self):
        post_id = self.request.get('post_id')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        db.delete(key)
        self.render('postdeleted.html')

class DeleteComment(BlogHandler):
    # This deletes blog comments
    def post(self):
        comment_id = self.request.get('comment_id')
        post_id = self.request.get('post_id')
        key = db.Key.from_path('Comments', int(comment_id), parent=post_key(post_id))
        db.delete(key)
        self.render('commentdeleted.html')

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        # renders signup form
        self.render("signup-form.html")

    def post(self):
        # Validates signup information and creates user account
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        # Takes login information, validates it and logins in user
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/post/([0-9]+)', LoadPost),
                               ('/blog/comment/([0-9]+)', LoadComment),
                               ('/blog/newpost', NewPost),
                               ('/blog/newcomment', NewComment),
                               ('/blog/editpost', EditPost),
                               ('/blog/editcomment', EditComment),
                               ('/blog/deletepost', DeletePost),
                               ('/blog/deletecomment', DeleteComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ],
                              debug=True)
