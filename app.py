import os

from flask import Flask, session, request, redirect, url_for, render_template
app = Flask(__name__, static_url_path='')
Flask.secret_key = 'andnowigetthehotreptilianking'

@app.route('/')
def index():
	return render_template('index.html')

# Fwol.in Authentication
# ----------------------

LOGIN_CALLBACK = 'http://fwol.in/login/'

@app.before_request
def fwolin_auth():
	if request.path != '/login/' and request.path != '/login':
		browserid = request.cookies.get('browserid')
		if not session.has_key('assertion') or session['assertion'] != browserid:
			return redirect('http://fwol.in/login/?callback=' + LOGIN_CALLBACK)

@app.route('/login/', methods=['GET'])
def login():
	assertion = request.cookies.get('browserid')
	if assertion:
		r = requests.post("https://browserid.org/verify", data={"assertion": assertion, "audience": "fwol.in"})
		ret = json.loads(r.text)
		if ret['status'] == 'okay':
			domain = re.sub(r'^[^@]+', '', ret['email'])
			if domain in ['@students.olin.edu', '@alumni.olin.edu', '@olin.edu']:
				session['assertion'] = assertion
				session['email'] = ret['email']
				return redirect(url_for('index'))
		else:
			request.set_cookie('browserid', None)

	return render_template('login.html')

# Launch
# ------

if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)