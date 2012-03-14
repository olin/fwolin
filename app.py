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
	return render_template('login.html')

# Launch
# ------

if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)