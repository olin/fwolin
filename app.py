import os, random, string, requests, json, re

from flask import Flask, session, request, redirect, url_for, render_template
app = Flask(__name__, static_url_path='')
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

LOGIN_CALLBACK = 'http://fwol.in/auth/'

@app.before_request
def fwolin_auth():
	if request.path not in ['/auth/', '/auth', '/login/', '/login']:
		assertion = request.cookies.get('browserid')
		if not session.has_key('assertion') or session['assertion'] != hashlib.sha1(assertion).hexdigest():
			return redirect('http://fwol.in/login/?callback=' + LOGIN_CALLBACK)

@app.route('/auth/', methods=['GET', 'POST'])
def auth():
	# Check browserid session is valid.
	assertion = request.cookies.get('browserid')
	if assertion and session.has_key('assertion') and session['assertion'] == hashlib.sha1(assertion).hexdigest():
		return redirect(url_for('index'))

	# Check new browserid assertion.
	if assertion:
		r = requests.post("https://browserid.org/verify", data={"assertion": assertion, "audience": "fwol.in"})
		ret = json.loads(r.text)
		if ret['status'] == 'okay':
			domain = re.sub(r'^[^@]+', '', ret['email'])
			if domain in ['@students.olin.edu', '@alumni.olin.edu', '@olin.edu']:
				session['assertion'] = hashlib.sha1(assertion).hexdigest()
				session['email'] = ret['email']
				return redirect(url_for('index'))

	# Fall through.
	return redirect(url_for('login', callback=LOGIN_CALLBACK))

# Launch
# ------

if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)