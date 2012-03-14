import os

from flask import Flask
from flask import render_template
app = Flask(__name__, static_url_path='')

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/login/')
def login():
	return render_template('login.html')

if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)