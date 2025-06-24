import os

# Base directory of the application
basedir = os.path.abspath(os.path.dirname(__file__))
# Base directory for storing website files
SITES_DIR = os.path.join(basedir, 'user_sites')


class Config:
    """Set Flask configuration variables."""

    # General Config
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    FLASK_APP = 'run.py'

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Custom App settings
    WEBSITES_BASE_FOLDER = SITES_DIR

