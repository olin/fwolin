import os, random, string, requests, json, re, time

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
		domain = re.sub(r'^[^@]+', '', ret['email'])
		if domain in ['@students.olin.edu', '@alumni.olin.edu', '@olin.edu']:
			session['assertion'] = hashlib.sha1(assertion).hexdigest()
			session['email'] = ret['email']
			session.permanent = True
			return True
	return False

@app.before_request
def fwolin_auth():
	if request.path in ['/login/', '/login']:
		return

	# Fallthrough.
	print '!!!!!!!! REQUEST PATH'
	response = redirect('http://fwol.in/login/?callback=' + request.path)
	# Check browser assertion.
	print '!!!!!!!! AND A COOKIE'
	assertion = request.cookies.get('browserid')
	print '!!!!!!!! SUP ASSERTION' + type(assertion)

	print('###ASSERTION: ' + assertion)
	if assertion:
		if 'assertion' in session and session['assertion'] == hashlib.sha1(assertion).hexdigest():
			print('###ASSERTION VALID')
			return
		if consume_assertion(assertion):
			print('###ASSERTION CONSUMED')
			return
		# Cookie is broke.
		print('###ASSERTION DEAD')
		response.set_cookie('browserid', value='', domain='.fwol.in', expires=time.time()-10000)
	print '!!!!!!!! BADIDEA ' + request.path
	return response

# Launch
# ------

if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)