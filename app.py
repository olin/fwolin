import os, random, string, requests, json, re
from pprint import pprint

from flask import Flask, session, request, redirect, url_for, render_template
app = Flask(__name__, static_url_path='')
app.config.update(
	SERVER_NAME='fwol.in'
)
Flask.secret_key = 'andnowigetthehotreptilianking'

# Routes
# ------

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/login/')
def login():
	return render_template('login.html')

# Fwol.in Authentication
# ----------------------

import hashlib

# Returns whether we can establish a session or not.
def consume_assertion(assertion):
	r = requests.post("https://browserid.org/verify", data={"assertion": assertion, "audience": "fwol.in"})
	ret = json.loads(r.text)
	if ret['status'] == 'okay':
		print('CONSUMPTION STATUS OKAY')
		domain = re.sub(r'^[^@]+', '', ret['email'])
		print('CONSUMPTION DOMAIN' + domain)
		if domain in ['@students.olin.edu', '@alumni.olin.edu', '@olin.edu']:
			session['assertion'] = hashlib.sha1(assertion).hexdigest()
			session['email'] = email
			return True
	print('CONSUMPTION FAILED')
	return False

@app.before_request
def fwolin_auth():
	if request.path in ['/login/', '/login']:
		return

	print('###Assertion for ' + request.path + ' is ' + request.cookies.get('browserid'))
	assertion = 'sadfadfsadfs'
	session['assertion'] = hashlib.sha1(assertion).hexdigest()
	return

	# Check browser assertion.
	assertion = request.cookies.get('browserid')
	print('ASSERTION: ' + request.path + ' AND THEN THIS ' + str(assertion))
	if assertion:
		print('### BROWSERID ASSERTION EXISTS ' + str('assertion' in session))
		if 'assertion' in session and session['assertion'] == hashlib.sha1(assertion).hexdigest():
			print('### ASSERTION SUCCESS')
			return
		if consume_assertion(assertion):
			print('### ASSERTION CONSUMED')
			return
			#return redirect(url_for('index'))
		# Cookie is broke.
		print('### COOKIE BROKEN, CLEAR')
	# Fallthrough.
	return redirect('http://fwol.in/login/?callback=' + request.path)

# Launch
# ------

if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)