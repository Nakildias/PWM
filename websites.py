import os
import subprocess
from flask import Flask, request
from datetime import date, datetime
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import requests
import json
import os

# Since this runs in a separate process, we need to set up the DB connection again.
# This is a simplified way to do it. A more robust solution might use a shared config.
basedir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')

engine = create_engine(SQLALCHEMY_DATABASE_URI)
Session = sessionmaker(bind=engine)

def geo_lookup_ip(ip_address):
    """
    Performs a Geo-IP lookup for a given IP address using ip-api.com.
    Returns a tuple (country_code, country_name) or (None, None) on failure.
    """
    if ip_address == '127.0.0.1': # Localhost, skip lookup
        return 'US', 'United States' # Default to US for localhost for testing
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=countryCode,country")
        response.raise_for_status() # Raise an exception for HTTP errors
        data = response.json()
        if data and data.get('status') == 'success':
            return data.get('countryCode'), data.get('country')
    except requests.exceptions.RequestException as e:
        print(f"Geo-IP lookup failed for {ip_address}: {e}")
    return None, None

def create_site_app(site_root_path, website_id):
    """
    Creates a simple Flask application instance for a user's website.
    This app serves static files from the user's site directory and tracks visits.
    """
    app = Flask(__name__, static_folder=site_root_path, static_url_path='')

    @app.before_request
    def track_visit():
        # This function will run before each request to the user's site
        db_session = Session()
        try:
            # We need a way to get the Visitor and Website models here.
            # A simple approach is to define them here again, but that's not ideal.
            # For now, let's assume we can execute a raw SQL query for simplicity.
            # A better way would be to share the models.
            today = date.today()
            now = datetime.utcnow()
            ip_address = request.remote_addr # Get client IP address

            country_code, country_name = geo_lookup_ip(ip_address)

            # Record individual visit
            db_session.execute(
                text("""INSERT INTO visit_log (website_id, ip_address, timestamp, country_code, country_name)
                   VALUES (:website_id, :ip_address, :timestamp, :country_code, :country_name)"""),
                {
                    'website_id': website_id,
                    'ip_address': ip_address,
                    'timestamp': now,
                    'country_code': country_code,
                    'country_name': country_name
                }
            )

            # Try to record a unique daily visit for this IP
            try:
                db_session.execute(
                    text("""INSERT INTO daily_unique_visitor (website_id, ip_address, date)
                       VALUES (:website_id, :ip_address, :date)"""),
                    {'website_id': website_id, 'ip_address': ip_address, 'date': today}
                )
                # If the above insert was successful, it's a new unique visit for the day
                db_session.execute(
                    text("""INSERT INTO visitor (website_id, date, daily_visits)
                       VALUES (:website_id, :date, 1)
                       ON CONFLICT(website_id, date) DO UPDATE SET daily_visits = daily_visits + 1"""),
                    {'website_id': website_id, 'date': today}
                )
                db_session.commit()
            except Exception as e:
                db_session.rollback()
                # print(f"Debug: IP {ip_address} already visited website {website_id} today or other error: {e}")
        except Exception as e:
            print(f"Error tracking visit for website {website_id}: {e}")
            db_session.rollback()
        finally:
            db_session.close()


    @app.route('/')
    def index():
        # This will serve the 'index.html' from the static_folder
        return app.send_static_file('index.html')

    return app

def run_website(site_root_path, port, website_id):
    """
    The target function for the subprocess. It creates and runs the site's Flask app.
    """
    site_app = create_site_app(site_root_path, website_id)
    # Running with debug=False is important for production-like environments
    site_app.run(host='0.0.0.0', port=port, debug=False)

