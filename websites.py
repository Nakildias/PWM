import os
from flask import Flask, request
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
import logging
from datetime import datetime

# Since this runs in a separate process, we need to set up the DB connection again.
# This is a simplified way to do it. A more robust solution might use a shared config.
basedir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')

engine = create_engine(SQLALCHEMY_DATABASE_URI)
Session = sessionmaker(bind=engine)

def create_site_app(site_root_path, website_id):
    """
    Creates a simple Flask application instance for a user's website.
    This app serves static files from the user's site directory.
    """
    app = Flask(__name__, static_folder=site_root_path, static_url_path='')

    # --- FIX: Ensure Werkzeug/Flask logs are directed to sys.stderr ---
    log = logging.getLogger('werkzeug')
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    )
    handler.setFormatter(formatter)

    # Clear existing handlers to prevent duplicate output
    log.handlers = []
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    # -----------------------------------------------------------------

    @app.route('/')
    def index():
        # This will serve the 'index.html' from the static_folder
        return app.send_static_file('index.html')

    @app.route('/<path:filename>')
    def serve_static(filename):
        # This allows serving files other than index.html from the root path
        return app.send_static_file(filename)


    return app

def run_website(site_root_path, port, website_id):
    """
    The target function for the subprocess. It creates and runs the site's Flask app.
    Redirects stdout/stderr to logs.txt.
    """
    log_file_path = os.path.join(site_root_path, 'logs.txt')

    # Open log file in append mode.
    with open(log_file_path, 'a', buffering=1) as log_file:

        # Temporarily redirect stdout and stderr to the log file
        # Note: Werkzeug's access logs go to stderr, which is captured here.
        sys.stdout = log_file
        sys.stderr = log_file

        # Print the startup message explicitly *after* redirection is active
        print(f"--- Serving Site ID {website_id} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---")

        try:
            site_app = create_site_app(site_root_path, website_id)
            # Running with debug=False is important for production-like environments
            # The logger config in create_site_app ensures Werkzeug access logs are captured.
            site_app.run(host='0.0.0.0', port=port, debug=False)
        finally:
            # IMPORTANT: Restore standard output/error streams when the process stops
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__
