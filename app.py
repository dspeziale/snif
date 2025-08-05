# app.py
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    """Dashboard principale"""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """Route alternativa per dashboard"""
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)

# requirements.txt
"""
Flask==2.3.3
"""

# Directory structure:
"""
project/
├── app.py
├── requirements.txt
├── static/
│   ├── css/
│   │   └── custom.css
│   ├── js/
│   │   └── custom.js
│   └── assets/
│       └── img/
└── templates/
    ├── base.html
    └── index.html
"""