import os
import subprocess
from flask import Flask

def create_site_app(site_root_path):
    """
    Creates a simple Flask application instance for a user's website.
    This app serves static files from the user's site directory.
    """
    app = Flask(__name__, static_folder=site_root_path, static_url_path='')

    @app.route('/')
    def index():
        # This will serve the 'index.html' from the static_folder
        return app.send_static_file('index.html')

    return app

def run_website(site_root_path, port):
    """
    The target function for the subprocess. It creates and runs the site's Flask app.
    """
    site_app = create_site_app(site_root_path)
    # Running with debug=False is important for production-like environments
    site_app.run(host='0.0.0.0', port=port, debug=False)

