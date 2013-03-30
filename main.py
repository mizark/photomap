import os
import re
import random
import hashlib
import hmac
from string import letters
import json
import urllib
import urllib2
import webapp2
import jinja2
import time


from google.appengine.api import images
from datetime import datetime, timedelta
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.ext import db
from google.appengine.api import memcache


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'eymangsupmang'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class SiteHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt=json.dumps(d)
        self.response.headers['Content-Type']='application/json; charset=UTF-8'
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
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
        
        if self.request.url.endswith('.json'):
            self.format='json'
        else:
            self.format='html'

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


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
    first_name=db.StringProperty()
    last_name=db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None,first_name=None, last_name=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email,
                    first_name=first_name,
                    last_name=last_name)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)


def top_posts(update=False):
    key='top'
    posts=memcache.get(key)
    if posts is None or update:
        posts=db.GqlQuery("SELECT * "
                         "FROM Post "
                         "ORDER BY created DESC "
                         "LIMIT 10")
        posts=list(posts)
        memcache.set(key,posts)
        
    return posts

def user_posts(username,update=False):
    key=str(username)
    posts=memcache.get(key)
    if posts is None or update:
        posts=db.GqlQuery("SELECT * FROM Post "
                          "WHERE postedby = :1 "
                          "ORDER BY created DESC",
                          username)
        posts=list(posts)
        memcache.set(key,posts)


    return posts

def category_posts(category, update=False):
    key=str(category)
    posts=memcache.get(key)
    if posts is None or update:
        posts=db.GqlQuery("SELECT * FROM Post "
                          "WHERE category= :1 "
                          "ORDER BY created DESC",
                          category)
        posts=list(posts)
        memcache.set(key,posts)

    return posts


def age_set(key, val):
    save_time=datetime.utcnow()
    memcache.set(key, (val,save_time))

def age_get(key):
    r=memcache.get(key)
    if r:
        val, save_time = r
        age = (datetime.utcnow() - save_time).total_seconds()
    else:
        val, age=None,0
    
    return val,age

def add_post(post):
    post.put()
    get_posts(update=True)
    return str(post.key().id())

def get_posts(update=False):
    q=Post.all().order('-created').fetch(limit=10)
    mc_key='BLOGS'

    posts, age=age_get(mc_key)
    if update or posts is None:
        posts=list(q)
        age_set(mc_key,posts)

    return posts, age

def age_str(age):
    s='Queried %s seconds ago'
    age=int(age)
    if age==1:
        s=s.replace('seconds','second')
    return s % age

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    postedby = db.StringProperty()
    category = db.StringProperty()
    
    permalink_url= db.StringProperty()
    photos= db.ListProperty(blobstore.BlobKey)
    photo_urls= db.ListProperty(str)
    photo_thumbs= db.ListProperty(str)
    photo_map=db.StringProperty()

    city_latitude=db.FloatProperty()
    city_longitude=db.FloatProperty()
    latitude_list=db.ListProperty(float)
    longitude_list=db.ListProperty(float)
    city=db.StringProperty()
    state=db.StringProperty()
    
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

    def as_dict(self):
        time_fmt="%c"
        d={'subject': self.subject,
           'content': self.content,
           'created': self.created.strftime(time_fmt),
           'last_modified': self.last_modified.strftime(time_fmt),
           'postedby': self.postedby,
           'category': self.category,
           'permalink_url':self.permalink_url,
           #'photos':self.photos,
           'photo_urls':self.photo_urls,
           'photo_thumbs':self.photo_thumbs,
           'photo_map':self.photo_map,
           'city_latitude':self.city_latitude,
           'city_longitude':self.city_longitude,
           'latitude_list':self.latitude_list,
           'longitude_list':self.longitude_list,
           'city':self.city,
           'state':self.state,
           }
        return d
           
class SiteFront(SiteHandler):
    def get(self):

        posts, age = get_posts()
        if self.format=='html':
            self.render('front.html', posts = posts, age=age_str(age))
        else:
            return self.render_json([p.as_dict() for p in posts])

class PostPage(SiteHandler):
    def get(self, post_id):
        post_key='POST_'+post_id
        post,age=age_get(post_key)
        
        if not post:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            age_set(post_key,post)
            age=0

        #permalink_url="/blog/%s"% str(post_id)


        if post is None:
            self.error(404)
            return
        if self.format=='html':
            self.render("permalink.html", post = post, age=age_str(age))
        else:
            self.render_json(post.as_dict())

class UserPage(SiteHandler):
    def get(self, username):
        if not self.user:
            self.redirect('/login')
        un=str(username)
        posts=user_posts(un)

        if self.format=='html':
            self.render('userposts.html', posts = posts, username=un)#, age=age_str(age))
        else:
            self.render_json([p.as_dict() for p in posts])

class CategoryPage(SiteHandler):
    def get(self, category):
        cat=str(category)
        posts=category_posts(cat)

        if self.format=='html':
            self.render('categoryposts.html', posts=posts, category=category)

        else:
            self.render_json([p.as_dict() for p in posts])

class NewPost(SiteHandler):
    def get(self):
        if self.user:
            upload_url=blobstore.create_upload_url('/upload')
            
            self.render("newpost.html", action=upload_url)
        else:
            self.redirect("/login")

class UploadHandler(blobstore_handlers.BlobstoreUploadHandler, SiteHandler):
  def post(self):
    upload_files = self.get_uploads('filesToUpload')

    error=''

    for x in upload_files:
      if x.content_type.split('/')[0] != 'image':
        error="All file uploads must be images of JPG, JPEG, or PNG format."
    
    if len(upload_files)>9:
        error=error+'\n'+"You may only upload 9 pictures max."
    
    subject = self.request.get('subject')
    if not subject:
        error=error+'\n'+"A subject is needed."

    city = self.request.get('city')
    if not city:
        error=error+'\n'+"A city is needed."

    state = self.request.get('state')
    if not state:
        error=error+'\n'+"A state is needed."

    content = self.request.get('content')
    if not content:
        error=error+'\n'+"A description is needed."  


    #map_URL='http://maps.googleapis.com/maps/api/staticmap?'+'center=%s,%s'%(str(latitude),str(longitude))+'&zoom=4'+'&size=500x500'+'&scale=2'+'&maptype=hybrid'+'&markers=%s,%s'%(str(latitude),str(longitude))+'&sensor=false'

  
    #self.response.out.write(latitude)
    #self.response.out.write(longitude)
    #self.response.out.write(f)
  #def temptempt(self):
    #postedby = self.user.name                                                                 

    if error == '':
      
      #Retreiving info about submission
      city=city.strip()
      city=city.replace(' ','+')
      state=state.strip()
      address=city+ ',+' + state

      data=urllib2.urlopen('http://maps.googleapis.com/maps/api/geocode/json?addr\
ess=%s&sensor=false'%address)
      j=json.load(data)
      city_latitude=float(j['results'][0]['geometry']['location']['lat'])
      city_longitude=float(j['results'][0]['geometry']['location']['lng'])

      postedby=self.user.name
      
      p = Post(parent = blog_key(), subject = subject,
               content = content, postedby=postedby,
               city_latitude=city_latitude,city_longitude=city_longitude,
               city=city,state=state )

      for file in upload_files:
        p.photos.append(file.key())
        p.photo_urls.append(images.get_serving_url(file.key(),secure_url=True))
        
        #Performing image transforms to allow for metadata extraction
        img=images.Image(blob_key=file.key())
        img.rotate(0)
        img.execute_transforms(output_encoding=images.JPEG,parse_source_metadata=True)
        f=img.get_original_metadata()

        if 'GPSLatitude' in f and 'GPSLongitude' in f:
            p.latitude_list.append(f['GPSLatitude'])
            p.longitude_list.append(f['GPSLongitude'])


      return_key=add_post(p)
      user_posts(postedby,True)
      p.permalink_url="/blog/%s"%return_key
      add_post(p)
      self.redirect("/blog/%s"%return_key)

    else:
      upload_url=blobstore.create_upload_url('/upload')
      self.render("newpost.html", action=upload_url,subject=subject,
                  content=content, error=error,city=city,state=state)

class ServeHandler(blobstore_handlers.BlobstoreDownloadHandler):
  def get(self, resource):
    resource = str(urllib.unquote(resource))
    blob_info=blobstore.BlobInfo.get(resource)
    self.send_blob(blob_info)


class Thumbnailer(blobstore_handlers.BlobstoreDownloadHandler,SiteHandler):
    def get(self,resource):
        blob_key=blobstore.BlobKey(resource)
        img=images.Image(blob_key=blob_key)
        img.resize(height=215, width=215)
        thumb=img.execute_transforms()
        self.response.out.write(thumb)
        return

class EnterPage(SiteHandler):
    def get(self):
        self.render("enter.html")




###### Signup

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(SiteHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
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
            u = User.register(self.username.lower(), self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(SiteHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username').lower()
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(SiteHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')
        #self.redirect('/signup')

class MainHandler(SiteHandler):
    def get(self):
        self.render('welcome.html')


class Invite(db.Model):
    email = db.StringProperty()
    
class InviteHandler(SiteHandler):

    def post(self):
        invite_email=self.request.get("email")
        
        if invite_email is None or invite_email=='':
            self.response.out.write("Email can't be blank!")

        elif valid_email(invite_email):
            temp=Invite(email=self.request.get("email"))
            temp.put()
            self.response.out.write('success')
        else:
            self.response.out.write('Sorry invalid email.')


app = webapp2.WSGIApplication([('/',SiteFront),
                               ('/blog/?(?:\.json)?', SiteFront),
                               ('/blog/([0-9]+)(?:\.json)?', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/user/([a-zA-Z0-9_-]+)(?:\.json)?', UserPage),
                              
                               ('/blog/category/([a-zA-Z0-9_-]+)(?:\.json)?', CategoryPage),
                               ('/upload', UploadHandler),
                               ('/serve/([^/]+)?',ServeHandler),
                               ('/thumbs/([^/]+)?',Thumbnailer),
                               ('/invites',InviteHandler)
                               ],debug=True)
'''

app = webapp2.WSGIApplication([('/', EnterPage),
                               ('/invites',InviteHandler) 
                               ],debug=True)
'''
