import os, random, string, requests, json, re, time
import hashlib, requests, json, time, os, re, urllib

from flask import Flask, session, request, redirect, url_for, render_template, jsonify, Response
app = Flask(__name__, static_url_path='')
Flask.secret_key = os.environ.get('FLASK_SESSION_KEY', os.environ.get('SECRET_KEY', 'test-key-please-ignore'))

PORT = int(os.environ.get('PORT', 5000))
if 'PORT' in os.environ:
	HOSTNAME = 'fwol.in'
	HOST = 'fwol.in'
else:
	HOSTNAME = 'localhost'
	HOST = 'localhost:5000'

# Mongo
# -----------

from pymongo import Connection, ASCENDING, DESCENDING
from bson.code import Code
from bson.objectid import ObjectId

if os.environ.has_key('MONGOLAB_URI'):
	mongodb_uri = os.environ['MONGOLAB_URI']
	db_name = 'heroku_app8341032'
else:
	mongodb_uri = "mongodb://localhost:27017/"
	db_name = 'fwolin'

connection = Connection(mongodb_uri)
db = connection[db_name]

def get_session_name():
	email = session.get('email', None)
	if not email:
		return None
	user = db.users.find_one(dict(email=email))
	if user:
		return user['nickname'] or user['name']
	return email.split('@', 1)[0].replace('.', ' ').title()

def ensure_session_user():
	email = session.get('email', None)
	if not email:
		return None
	if not db.users.find_one(dict(email=email)):
		db.users.insert(dict(
			email=email,
			name=get_session_name(),
			nickname='',
			room='',
			avatar='',
			phone='',
			year=''
		))
	return db.users.find_one(dict(email=session['email']))

USER_KEYS = ['name', 'nickname', 'room', 'avatar', 'year', 'phone',
	'twitter', 'facebook', 'tumblr', 'skype', 'pinterest', 'lastfm'];

def db_user_json(user):
	json = dict(id=str(user['_id']), email=user['email']);
	for key in USER_KEYS:
		json[key] = user.get(key, '')
	return json

# Auth
# -----------

import urllib2, re, getpass, urllib2, base64
from urllib2 import URLError
from ntlm import HTTPNtlmAuthHandler

def network_login(dn, user, password):
	try:
		url = "https://webmail.olin.edu/ews/exchange.asmx"

		# setup HTTP password handler
		passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
		passman.add_password(None, url, dn + '\\' + user, password)
		# create NTLM authentication handler
		auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)
		proxy_handler =  urllib2.ProxyHandler({})
		opener = urllib2.build_opener(proxy_handler,auth_NTLM)

		# this function sends the custom SOAP command which expands
		# a given distribution list
		data = """<?xml version="1.0" encoding="utf-8"?>
	<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
		           xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
	  <soap:Body>
	  <ResolveNames xmlns="http://schemas.microsoft.com/exchange/services/2006/messages"
	                xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
	                ReturnFullContactData="true">
	    <UnresolvedEntry>%s</UnresolvedEntry>
	  </ResolveNames>
	  </soap:Body>
	</soap:Envelope>
	""" % user
		# send request
		headers = {'Content-Type': 'text/xml; charset=utf-8'}
		req = urllib2.Request(url, data=data, headers=headers)
		res = opener.open(req).read()

		# parse result
		return re.search(r'<t:EmailAddress>([^<]+)</t:EmailAddress>', res).group(1)
	except Error, e:
		return False

# Returns whether we can establish a session or not.
def _consume_assertion(assertion):
	r = requests.post("https://browserid.org/verify", data={"assertion": assertion, "audience": '%s' % HOST})
	ret = json.loads(r.text)
	if ret['status'] == 'okay':
		domain = re.sub(r'^[^@]+', '', ret['email'])
		if domain in ['@students.olin.edu', '@alumni.olin.edu', '@olin.edu']:
			session['email'] = ret['email'].lower()
			session.permanent = True
			ensure_session_user()
			return True
	return False

AUTH_CACHE = dict()

# Enable authentication on an application.
def enable_auth(app, blacklist, unauthed):
	@app.before_request
	def auth():
		# LDAP authorization.
		if request.headers.get('Authorization'):
			if AUTH_CACHE.get(request.headers.get('Authorization')):
				session['email'] = AUTH_CACHE.get(request.headers.get('Authorization'))
			elif request.headers.get('Authorization', '')[0:6] == 'Basic ':
				bundle = base64.b64decode(request.headers.get('Authorization', '')[6:])
				if bundle.find(':') > -1:
					try:
						username, password = bundle.split(':')
						email = network_login('MILKYWAY', username, password)
						if email:
							AUTH_CACHE[request.headers.get('Authorization')] = email.lower()
							session['email'] = email.lower()
					except Exception, e:
						pass

		if not session.get('email'):
			for item in blacklist:
				if item == '*' or request.path.startswith(item):
					return unauthed()

# Routes
# ------

@app.route('/')
def index():
	return render_template('index.html',
		email=session.get('email', None),
		name=get_session_name())

@app.route('/calendar/')
def calendar():
	return render_template('calendar.html',
		email=session.get('email', None),
		name=get_session_name())

@app.route('/directory/')
def directory():
	user = ensure_session_user()
	return render_template('directory.html',
		email=session.get('email', None),
		name=get_session_name(),
		user=db_user_json(ensure_session_user()),
		people=[db_user_json(user) for user in db.users.find().sort('name', 1)])

# Login/out

@app.route('/login/', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		_consume_assertion(request.form['assertion'])
		return redirect('/')
	else:
		if request.args.get('callback', None) and session.get('email', None):
			if re.match(r'^http://([a-z_\-]+\.olinapps\.com|localhost(:[0-9]+)?)\/', request.args['callback']):
				return redirect(request.args['callback'] + '?code=' + urllib.quote_plus(request.cookies.get(app.session_cookie_name)))
			else:
				return Response(json.dumps(dict(error='Invalid callback domain: ' + request.args['callback'])), 400, {'content-type': 'application/json'})
		if session.get('email'):
			return redirect('/directory/')
		return render_template('login.html',
			email=session.get('email', None),
			name=(session.get('email', '') or '').split('@')[0])

@app.route('/logout/', methods=['GET', 'POST'])
def logout():
	if request.method == 'POST':
		session['email'] = None
	return redirect('/')

# API

@app.route('/api/me', methods=['GET', 'POST'])
def api_me():
	user = ensure_session_user()
	if request.method == 'POST':
		for key in USER_KEYS:
			if request.form.has_key(key):
				user[key] = request.form[key]
		db.users.update({"_id": user['_id']}, user)
		return redirect('/directory/')

	return jsonify(**db_user_json(user))

@app.route('/api/people')
def api_people():
	return jsonify(people=[db_user_json(user) for user in db.users.find().sort('name', 1)])

# Fwol.in Authentication
# ----------------------

def fwolin_unauthed():
	if request.path.startswith('/api/'):
		return Response(json.dumps({"error": "Unauthorized"}), 401, {'Content-Type': 'application/json'})
	else:
		return redirect('/login/')

# All pages are accessible, but enable user accounts.
enable_auth(app, ['/api/', '/directory/'], fwolin_unauthed)

# Launch
# ------

if __name__ == '__main__':
	# Bind to PORT if defined, otherwise default to 5000.
	app.debug = True
	app.run(host=HOSTNAME, port=PORT)
