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

AUTH_CACHE = dict()

# Enable authentication on an application.
def enable_auth(app, whitelist=[]):
	@app.before_request
	def auth():
		# LDAP authorization.
		if request.headers.get('Authorization'):
			if AUTH_CACHE.get(request.headers.get('Authorization')):
				session['email'] = AUTH_CACHE.get(request.headers.get('Authorization'))
			elif request.headers.get('Authorization', '')[0:6] == 'Basic ':
				#bundle = base64.b64decode(request.headers.get('Authorization', '')[5])
				bundle = request.headers.get('Authorization', '')[6:]
				if bundle.find(':') > -1:
					try:
						username, password = bundle.split(':')
						email = network_login('MILKYWAY', username, password)
						print email
						if email:
							AUTH_CACHE[request.headers.get('Authorization')] = email
							session['email'] = email
					except Error, e:
						print e
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
