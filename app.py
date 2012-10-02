import os, random, string, requests, json, re, time, fwolin

from flask import Flask, session, request, redirect, url_for, render_template
app = Flask(__name__, static_url_path='')
Flask.secret_key = os.environ.get('FLASK_SESSION_KEY', 'test-key-please-ignore')

# Routes
# ------

@app.route('/')
def index():
	return render_template('index.html',
		email=session.get('email', None),
		name=session.get('email', None).split('@')[0])

@app.route('/login/')
def login():
	return render_template('login.html')

@app.route('/calendar/')
def calendar():
	return render_template('calendar.html')

# Fwol.in Authentication
# ----------------------

# All pages are accessible, but enable user accounts.
fwolin.enable_auth(app, None, ['*'])

# Launch
# ------

if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.debug = True
    if 'PORT' in os.environ:
    	app.config.update(SERVER_NAME='fwol.in')
    app.run(host='0.0.0.0', port=port)
