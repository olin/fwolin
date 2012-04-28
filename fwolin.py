import hashlib, requests, json, time, os, re
from flask import session, request, redirect

# Returns whether we can establish a session or not.
def _consume_assertion(assertion):
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

def _logged_in(newlogin):
	return

def _fwolin_auth(logged_in, whitelist):
	if request.path in whitelist:
		return

	# Fallthrough.
	response = redirect('http://fwol.in/login/?callback=' + request.url)
	# Check browser assertion.
	assertion = request.cookies.get('browserid')
	if assertion:
		if session.get('assertion', '') == hashlib.sha1(assertion).hexdigest():
			logged_in(False)
			return
		if _consume_assertion(assertion):
			logged_in(True)
			return
		# Cookie is broke.
		response.set_cookie('browserid', value='', domain='.fwol.in', expires=time.time()-10000)
	return response

def _fake_auth(logged_in, whitelist):
	if request.path in whitelist:
		return

	session['email'] = os.environ['FWOLIN_EMAIL']
	logged_in(False)

# Enable authentication on an application.
def enable_auth(app, logged_in=None, whitelist=[]):
	if not logged_in:
		logged_in = _logged_in

	if 'FWOLIN_EMAIL' in os.environ:
		print('Using environment Fwolin credentials: ' + os.environ['FWOLIN_EMAIL'])
		@app.before_request
		def auth():
			return _fake_auth(logged_in, whitelist)

	else:
		@app.before_request
		def auth():
			return _fwolin_auth(logged_in, whitelist)