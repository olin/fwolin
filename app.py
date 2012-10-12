#s
import os, random, string, requests, json, re, time
import hashlib, requests, json, time, os, re

from flask import Flask, session, request, redirect, url_for, render_template
app = Flask(__name__, static_url_path='')
Flask.secret_key = os.environ.get('FLASK_SESSION_KEY', 'test-key-please-ignore')

PORT = int(os.environ.get('PORT', 5000))
if 'PORT' in os.environ:
	HOST = 'fwol.in'
else:
	HOST = 'localhost'

# Auth
# -----------

import ldap, base64

LDAP_SERVER = "ldap://ldap.olin.edu"

def ldap_auth(server, username, dn, secret):
	try:
		dn = dn + "\\" + username

		ldap.set_option(ldap.OPT_REFERRALS, 0)
		l = ldap.initialize(server)
		l.protocol_version = 3
		l.simple_bind_s(dn, secret)

		## The next lines will also need to be changed to support your search requirements and directory
		baseDN = "dc=olin,dc=edu"
		searchScope = ldap.SCOPE_SUBTREE
		## retrieve all attributes - again adjust to your needs - see documentation for more options
		retrieveAttributes = None 
		searchFilter = "sAMAccountName=%s" % username

		ldap_result_id = l.search(baseDN, searchScope, searchFilter, retrieveAttributes)
		result_set = []
		while 1:
			result_type, result_data = l.result(ldap_result_id, 0)
			if (result_data == []):
				break
			else:
				## here you don't have to append to a list
				## you could do whatever you want with the individual entry
				## The appending to list is just for illustration. 
				if result_type == ldap.RES_SEARCH_ENTRY:
					return result_data[0][1]['mail'][0]

	except ldap.INVALID_CREDENTIALS, e:
		print e
		return False

# Returns whether we can establish a session or not.
def _consume_assertion(assertion):
	r = requests.post("https://browserid.org/verify", data={"assertion": assertion, "audience": '%s:%s' % (HOST, PORT)})
	ret = json.loads(r.text)
	if ret['status'] == 'okay':
		domain = re.sub(r'^[^@]+', '', ret['email'])
		if domain in ['@students.olin.edu', '@alumni.olin.edu', '@olin.edu']:
			session['email'] = ret['email']
			session.permanent = True
			return True
	return False

LDAP_CACHE = dict()

# Enable authentication on an application.
def enable_auth(app, whitelist=[]):
	@app.before_request
	def auth():
		# LDAP authorization.
		if request.headers.get('Authorization'):
			if LDAP_CACHE.get(request.headers.get('Authorization')):
				session['email'] = LDAP_CACHE.get(request.headers.get('Authorization'))
			elif request.headers.get('Authorization', '')[0:5] == 'LDAP ':
				#bundle = base64.b64decode(request.headers.get('Authorization', '')[5])
				bundle = request.headers.get('Authorization', '')[5:]
				if bundle.find(':') > -1:
					try:
						username, password = bundle.split(':')
						email = ldap_auth(LDAP_SERVER, username, "MILKYWAY", password)
						if email:
							LDAP_CACHE[request.headers.get('Authorization')] = email
							session['email'] = email
					except:
						pass

		if request.path in whitelist or '*' in whitelist:
			return
		# Redo redirect
		return redirect('/')

# Routes
# ------

@app.route('/')
def index():
	print(session.get('email', ''))
	return render_template('index.html',
		email=session.get('email', None),
		name=(session.get('email', '') or '').split('@')[0])

@app.route('/login/', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		_consume_assertion(request.form['assertion'])
		return redirect('/')
	else:
		return render_template('login.html')

@app.route('/logout/', methods=['GET', 'POST'])
def logout():
	if request.method == 'POST':
		session['email'] = None
	return redirect('/')

@app.route('/calendar/')
def calendar():
	return render_template('calendar.html',
		email=session.get('email', None),
		name=(session.get('email', '') or '').split('@')[0])

# Fwol.in Authentication
# ----------------------

# All pages are accessible, but enable user accounts.
enable_auth(app, ['*'])

# Launch
# ------

if __name__ == '__main__':
	# Bind to PORT if defined, otherwise default to 5000.
	app.debug = True
	if 'PORT' in os.environ:
		app.config.update(SERVER_NAME='fwol.in')
	app.run(host=HOST, port=PORT)
