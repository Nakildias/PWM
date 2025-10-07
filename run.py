import os
import subprocess
import sys
import shutil
from multiprocessing import Process, active_children
from flask import Flask, render_template, redirect, url_for, flash, session, request, send_from_directory, abort, jsonify, Response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, NumberRange
from datetime import date, datetime, timedelta
import config
import websites
import tempfile
import json
import hashlib

# Keep track of running processes
running_processes = {}

# -----------------------------------------------------------------------------
# App Initialization & Models & Forms
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(config.Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    websites = db.relationship('Website', backref='owner', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Website(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    port = db.Column(db.Integer, unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    process_id = db.Column(db.Integer, nullable=True)
    autostart = db.Column(db.Boolean, default=False, nullable=False)
    live_view_url = db.Column(db.String(255), nullable=True) # New field for custom live view URL

    __table_args__ = (db.UniqueConstraint('user_id', 'name', name='_user_id_name_uc'),)

class AppSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(100), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class WebsiteForm(FlaskForm):
    name = StringField('Website Name', validators=[DataRequired(), Length(min=3, max=50)])
    port = IntegerField('Port', validators=[DataRequired(), NumberRange(min=1024, max=65535)])
    submit = SubmitField('Create Website')

    def validate_name(self, name):
        site = Website.query.filter_by(name=name.data, user_id=current_user.id).first()
        if site:
            raise ValidationError('You already have a website with this name.')

    def validate_port(self, port):
        site = Website.query.filter_by(port=port.data).first()
        if site:
            raise ValidationError('This port is already in use. Please choose another.')

class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('New Password (leave blank to keep current)')
    confirm_password = PasswordField('Confirm New Password', validators=[EqualTo('password', message='Passwords must match')])
    is_admin = BooleanField('Is Admin')
    submit = SubmitField('Update User')

    def __init__(self, original_username, user_id, *args, **kwargs):
        super(EditUserForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.user_id = user_id

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=username.data).first()
            if user and user.id != self.user_id:
                raise ValidationError('That username is taken. Please choose a different one.')

class EditWebsiteForm(FlaskForm):
    name = StringField('Website Name', validators=[DataRequired(), Length(min=3, max=50)])
    port = IntegerField('Port', validators=[DataRequired(), NumberRange(min=1024, max=65535)])
    live_view_url = StringField('Live View URL (Optional)')
    submit = SubmitField('Update Website')

    def __init__(self, original_name, original_port, user_id, *args, **kwargs):
        super(EditWebsiteForm, self).__init__(*args, **kwargs)
        self.original_name = original_name
        self.original_port = original_port
        self.user_id = user_id

    def validate_name(self, name):
        if name.data != self.original_name:
            site = Website.query.filter_by(name=name.data, user_id=self.user_id).first()
            if site:
                raise ValidationError('You already have a website with this name.')

    def validate_port(self, port):
        if port.data != self.original_port:
            site = Website.query.filter_by(port=port.data).first()
            if site:
                raise ValidationError('This port is already in use. Please choose another.')

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
def get_next_available_port():
    base_port = 5001
    used_ports = {site.port for site in Website.query.all()}
    port = base_port
    while port in used_ports:
        port += 1
    return port

def get_site_base_path(site):
    """Returns the base directory path for a given site."""
    return os.path.join(config.Config.WEBSITES_BASE_FOLDER, str(site.user_id), site.name)

def get_safe_path(site, unsafe_path=''):
    """
    Constructs a safe, absolute path for a file or directory within a site's folder.
    Prevents directory traversal attacks.
    """
    base_path = get_site_base_path(site)
    # The 'index.html' path is special, as the user only edits that.
    if unsafe_path.lower() == 'index.html':
         full_path = os.path.realpath(os.path.join(base_path, 'index.html'))
    else:
        full_path = os.path.realpath(os.path.join(base_path, unsafe_path))

    if os.path.commonprefix([full_path, base_path]) != base_path:
        abort(403) # Forbidden

    return full_path

def get_history_path(site):
    """Returns the base directory path for the site's history."""
    return os.path.join(get_site_base_path(site), 'history')

def calculate_content_hash(content):
    """Calculates the SHA256 hash of file content."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def create_file_backup(site, filename='index.html', content=None):
    """
    Creates a timestamped backup of a file in the site's history folder.
    Returns a dict with status and message.
    """
    base_path = get_site_base_path(site)
    file_path = os.path.join(base_path, filename)
    history_dir = get_history_path(site)
    os.makedirs(history_dir, exist_ok=True)

    # 1. Determine content to be backed up
    if content is None:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content_to_hash = f.read()
        except FileNotFoundError:
            return {'status': 'error', 'message': f'Original file {filename} not found.'}
    else:
        content_to_hash = content

    if not content_to_hash.strip():
        return {'status': 'warning', 'message': 'Skipped backup: Content is empty.'}

    current_content_hash = calculate_content_hash(content_to_hash)

    # 2. Check for existing identical backups and manage duplicates
    history_items = get_history_items(site, filename=filename, include_hash=True)
    duplicate_found = False
    duplicate_name = None

    for item in history_items:
        if item.get('content_hash') == current_content_hash:
            duplicate_found = True
            duplicate_name = item['name']
            break

    if duplicate_found:
        # If duplicate is found, delete the old one to "move" the backup time
        try:
            os.remove(os.path.join(history_dir, duplicate_name))
        except Exception as e:
            print(f"Error deleting old duplicate backup {duplicate_name}: {e}")
            return {'status': 'error', 'message': f'Failed to clear old duplicate backup: {duplicate_name}.'}

    # 3. Create the new backup
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"{filename}.{timestamp}.bak"
    backup_path = os.path.join(history_dir, backup_filename)

    try:
        with open(backup_path, 'w', encoding='utf-8') as f:
            f.write(content_to_hash)

        if duplicate_found:
            return {
                'status': 'info',
                'message': f'Backup refreshed (duplicate replaced): {timestamp}.',
                'backup_name': backup_filename
            }
        else:
            return {
                'status': 'success',
                'message': f'File saved and new backup created: {timestamp}.',
                'backup_name': backup_filename
            }
    except Exception as e:
        print(f"Error saving backup: {e}")
        return {'status': 'error', 'message': f'Error saving backup: {e}.'}


def get_history_items(site, filename='index.html', include_hash=False):
    """Returns a list of history items (backups) for a given file, including size."""
    history_dir = get_history_path(site)
    if not os.path.exists(history_dir):
        return []

    items_to_sort = []
    for item_name in os.listdir(history_dir):
        if item_name.startswith(f"{filename}.") and item_name.endswith(".bak"):
            parts = item_name.split('.')
            if len(parts) == 4:
                # Correctly grab the TIMESTAMP part at index 2
                timestamp_str = parts[2]
                backup_path = os.path.join(history_dir, item_name)
                try:
                    dt = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                    size_bytes = os.path.getsize(backup_path) if os.path.exists(backup_path) else 0

                    item = {
                        'name': item_name,
                        'timestamp_dt': dt,
                        'timestamp': dt.isoformat(), # ISO format for easy JS calculation
                        'display': dt.strftime("%Y-%m-%d %H:%M:%S"),
                        'size_bytes': size_bytes
                    }

                    if include_hash:
                        # Only calculate hash if requested
                        with open(backup_path, 'r', encoding='utf-8') as f:
                            item['content_hash'] = calculate_content_hash(f.read())

                    items_to_sort.append(item)
                except ValueError:
                    continue
                except Exception:
                    continue # Skip item if file read/hash fails

    # Sort by newest first
    items_to_sort.sort(key=lambda x: x['timestamp_dt'], reverse=True)

    # Remove timestamp_dt before returning JSON
    for item in items_to_sort:
        del item['timestamp_dt']
        if not include_hash:
            # Also remove hash if we were only using it internally for sorting/checking
            item.pop('content_hash', None)


    return items_to_sort

def cleanup_processes():
    print("Shutting down... terminating all running websites.")
    for pid in running_processes:
        try:
            p = running_processes[pid]
            p.terminate()
            p.join(timeout=2)
            print(f"Terminated process {pid}")
        except Exception as e:
            print(f"Error terminating process {pid}: {e}")
    for child in active_children():
        child.terminate()
        child.join()

def get_codemirror_themes():
    # A selection of themes available from cdnjs
    return [
        "default", "3024-day", "3024-night", "abcdef", "ambiance",
        "ayu-dark", "ayu-mirage", "base16-dark", "base16-light", "bespin",
        "blackboard", "cobalt", "colorforth", "darcula", "dracula", "duotone-dark",
        "duotone-light", "eclipse", "elegant", "erlang-dark", "gruvbox-dark",
        "hopscotch", "icecoder", "idea", "isotope", "juejin", "lesser-dark",
        "liquibyte", "lucario", "material", "material-darker", "material-palenight",
        "material-ocean", "mbo", "mdn-like", "midnight", "monokai", "moxer",
        "neat", "neo", "night", "nord", "oceanic-next", "panda-syntax",
        "paraiso-dark", "paraiso-light", "pastel-on-dark", "railscasts",
        "rubyblue", "seti", "shadowfox", "solarized", "the-matrix",
        "tomorrow-night-bright", "tomorrow-night-eighties", "ttcn", "twilight",
        "vibrant-ink", "xq-dark", "xq-light", "yeti", "yonce", "zenburn"
    ]
# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard/')
@login_required
def dashboard():
    form = WebsiteForm()
    form.port.data = get_next_available_port()
    user_websites = Website.query.filter_by(user_id=current_user.id).all()
    codemirror_theme_setting = AppSetting.query.filter_by(key='codemirror_theme').first()
    codemirror_theme = codemirror_theme_setting.value if codemirror_theme_setting else 'default'
    return render_template('dashboard.html', title='Dashboard', sites=user_websites, form=form, running_processes=running_processes,  codemirror_theme=codemirror_theme)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    registration_setting = AppSetting.query.filter_by(key='allow_registration').first()
    if registration_setting and registration_setting.value == 'false':
        flash('User registration is currently disabled.', 'warning')
        return redirect(url_for('login'))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        if User.query.count() == 0:
            user.is_admin = True
        db.session.add(user)
        db.session.commit()
        flash(f'Account created for {form.username.data}! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    registration_setting = AppSetting.query.filter_by(key='allow_registration').first()
    allow_registration = registration_setting.value == 'true' if registration_setting else True

    codemirror_theme_setting = AppSetting.query.filter_by(key='codemirror_theme').first()
    codemirror_theme = codemirror_theme_setting.value if codemirror_theme_setting else 'default'

    return render_template('admin.html',
                           title='Admin Panel',
                           allow_registration=allow_registration,
                           codemirror_theme=codemirror_theme,
                           themes=get_codemirror_themes())

@app.route('/admin/toggle_registration')
@login_required
def toggle_registration():
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('dashboard'))

    setting = AppSetting.query.filter_by(key='allow_registration').first()
    if setting:
        setting.value = 'false' if setting.value == 'true' else 'true'
    else:
        setting = AppSetting(key='allow_registration', value='false')
        db.session.add(setting)

    db.session.commit()
    flash(f"User registration has been {'enabled' if setting.value == 'true' else 'disabled'}.", 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/set_theme', methods=['POST'])
@login_required
def set_codemirror_theme():
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('dashboard'))

    theme = request.form.get('theme')
    setting = AppSetting.query.filter_by(key='codemirror_theme').first()
    if setting:
        setting.value = theme
    else:
        setting = AppSetting(key='codemirror_theme', value=theme)
        db.session.add(setting)
    db.session.commit()
    flash(f'CodeMirror theme has been set to {theme}.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/users')
@login_required
def manage_users():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    users = User.query.all()
    return render_template('manage_users.html', title='Manage Users', users=users)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('dashboard'))

    user = db.get_or_404(User, user_id)
    form = EditUserForm(original_username=user.username, user_id=user.id)

    if form.validate_on_submit():
        user.username = form.username.data

        if form.password.data: # Only update password if a new one is provided
            user.set_password(form.password.data)

        # Prevent non-admin user from revoking their own admin status
        if user.id == current_user.id and not form.is_admin.data:
            flash("You cannot revoke your own admin privileges.", 'danger')
            return redirect(url_for('edit_user', user_id=user.id))

        user.is_admin = form.is_admin.data

        db.session.commit()
        flash(f'User "{user.username}" updated successfully!', 'success')
        return redirect(url_for('manage_users'))
    elif request.method == 'GET':
        form.username.data = user.username
        form.is_admin.data = user.is_admin

    return render_template('edit_user.html', title=f'Edit User: {user.username}', form=form, user=user)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('dashboard'))

    user_to_delete = db.get_or_404(User, user_id)

    if user_to_delete.id == current_user.id:
        flash("You cannot delete your own account.", 'danger')
        return redirect(url_for('manage_users'))

    username = user_to_delete.username
    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f'User "{username}" and all their associated websites have been deleted.', 'success')
    return redirect(url_for('manage_users'))


# --- Website Management Routes ---

@app.route('/website/create', methods=['POST'])
@login_required
def create_website():
    form = WebsiteForm()
    if form.validate_on_submit():
        new_site = Website(name=form.name.data, port=form.port.data, owner=current_user)
        db.session.add(new_site)
        db.session.commit()

        site_path = get_site_base_path(new_site)
        os.makedirs(os.path.join(site_path, 'static', 'css'), exist_ok=True)
        os.makedirs(os.path.join(site_path, 'static', 'js'), exist_ok=True)

        with open(os.path.join(site_path, 'index.html'), 'w') as f:
            f.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{new_site.name}</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div style="padding: 20px; text-align: center;">
        <h1>Welcome to {new_site.name}!</h1>
        <p>Your website is running on port {new_site.port}.</p>
        <p>Edit this file using the "Modify" button on the Dashboard!</p>
    </div>
    <script src="/static/js/main.js"></script>
</body>
</html>""")

        with open(os.path.join(site_path, 'static', 'css', 'style.css'), 'w') as f:
            f.write(f"body {{ background-color: #f0f0f0; font-family: sans-serif; }} h1 {{ color: #333; }}")

        with open(os.path.join(site_path, 'static', 'js', 'main.js'), 'w') as f:
            f.write(f"// Your JavaScript code goes here\n")


        flash(f'Website "{new_site.name}" created successfully!', 'success')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {getattr(form, field).label.text}: {error}", 'danger')
    return redirect(url_for('dashboard'))

@app.route('/website/start/<int:site_id>')
@login_required
def start_website(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        flash('You do not have permission to manage this site.', 'danger')
        return redirect(url_for('dashboard'))

    if site.id in running_processes and running_processes[site.id].is_alive():
        flash(f'Website "{site.name}" is already running.', 'warning')
        return redirect(url_for('dashboard'))

    site_path = get_site_base_path(site)
    # Ensure logs.txt file exists before starting the process
    log_file_path = os.path.join(site_path, 'logs.txt')
    if not os.path.exists(log_file_path):
        try:
            os.makedirs(site_path, exist_ok=True)
            with open(log_file_path, 'w') as f:
                f.write(f"--- Log file created at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
        except Exception as e:
            flash(f'Error creating log file: {e}', 'danger')
            return redirect(url_for('dashboard'))


    process = Process(target=websites.run_website, args=(site_path, site.port, site.id))
    process.start()

    site.process_id = process.pid
    running_processes[site.id] = process
    db.session.commit()

    flash(f'Website "{site.name}" started on port {site.port}.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/website/stop/<int:site_id>')
@login_required
def stop_website(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        flash('You do not have permission to manage this site.', 'danger')
        return redirect(url_for('dashboard'))

    if site.id in running_processes and running_processes[site.id].is_alive():
        p = running_processes.pop(site.id)
        p.terminate()
        p.join()
        site.process_id = None
        db.session.commit()
        flash(f'Website "{site.name}" stopped.', 'success')
    else:
        flash(f'Website "{site.name}" is not running.', 'warning')
        if site.process_id is not None:
             site.process_id = None
             db.session.commit()

    return redirect(url_for('dashboard'))

@app.route('/website/toggle_autostart/<int:site_id>')
@login_required
def toggle_autostart(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    site.autostart = not site.autostart
    db.session.commit()
    status = "enabled" if site.autostart else "disabled"
    flash(f'Auto-start for "{site.name}" has been {status}.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/website/backup/<int:site_id>')
@login_required
def backup_website(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    site_path = get_site_base_path(site)
    # Create a base name that includes the site name and a timestamp
    base_name = f"{secure_filename(site.name)}-backup-{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Define a unique path for the temporary zip file
    zip_base_path = os.path.join(tempfile.gettempdir(), base_name)

    # Create the zip archive (shutil.make_archive returns the full path including .zip extension)
    archive_path = shutil.make_archive(
        zip_base_path,
        'zip',
        root_dir=os.path.dirname(site_path),
        base_dir=os.path.basename(site_path)
    )

    # Send the file for download. Flask/Werkzeug will handle cleanup eventually.
    return send_file(
        archive_path,
        mimetype='application/zip',
        as_attachment=True,
        download_name=os.path.basename(archive_path),
        max_age=0  # Prevent caching
    ), 200, {'X-Accel-Buffering': 'no'}


@app.route('/website/delete/<int:site_id>', methods=['POST'])
@login_required
def delete_website(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        flash('You do not have permission to delete this site.', 'danger')
        return redirect(url_for('dashboard'))

    if site.id in running_processes and running_processes[site.id].is_alive():
        p = running_processes.pop(site.id)
        p.terminate()
        p.join()

    site_path = get_site_base_path(site)
    if os.path.exists(site_path):
        shutil.rmtree(site_path)

    db.session.delete(site)
    db.session.commit()
    flash(f'Website "{site.name}" and all its files have been deleted.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/website/edit/<int:site_id>', methods=['POST'])
@login_required
def edit_website(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    # Note: We create a dummy form instance here, passing the current (original) site data
    # as the EditWebsiteForm validator needs the original data to check for unique constraints
    # against other sites/users.
    form = EditWebsiteForm(
        original_name=site.name,
        original_port=site.port,
        user_id=current_user.id,
        name=request.form.get('name'),
        port=request.form.get('port'),
        live_view_url=request.form.get('live_view_url')
    )

    # We must manually set the form data from the POST request since we didn't use
    # Flask-WTF's automatic data population by not passing form=form in a GET context.
    form.name.data = request.form.get('name')
    form.live_view_url.data = request.form.get('live_view_url')
    # Convert port string to integer for validation
    try:
        form.port.data = int(request.form.get('port'))
    except (ValueError, TypeError):
        form.port.data = None # Let validation fail on its own if necessary

    if form.validate_on_submit():
        original_site_path = get_site_base_path(site)
        old_name = site.name

        site.name = form.name.data
        site.port = form.port.data
        site.live_view_url = form.live_view_url.data or None # Save the new field
        db.session.commit()

        new_site_path = get_site_base_path(site)
        if original_site_path != new_site_path:
            try:
                os.rename(original_site_path, new_site_path)
            except OSError as e:
                # If rename fails, flash error but keep going
                flash(f'Error renaming website folder from "{old_name}" to "{site.name}": {e}', 'danger')

        flash(f'Website "{site.name}" updated successfully!', 'success')
    else:
        # If validation fails, flash all errors and redirect back to the dashboard
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error updating site settings (Field: {getattr(form, field).label.text}): {error}", 'danger')

    return redirect(url_for('dashboard'))

# --- Live Editor Routes (NEW) ---

@app.route('/website/live_edit/<int:site_id>')
@login_required
def live_edit(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    files_to_edit = {
        'html': {'path': 'index.html', 'default_content': '<!DOCTYPE html>\n<html>\n<head>\n  <title>My Site</title>\n  <link rel="stylesheet" href="/static/css/style.css">\n</head>\n<body>\n  <h1>Hello, World!</h1>\n  <script src="/static/js/main.js"></script>\n</body>\n</html>'},
        'css': {'path': os.path.join('static', 'css', 'style.css'), 'default_content': 'body {\n  font-family: sans-serif;\n}'},
        'js': {'path': os.path.join('static', 'js', 'main.js'), 'default_content': '// Your JavaScript code here'}
    }

    content = {}
    for key, file_info in files_to_edit.items():
        file_path_full = get_safe_path(site, file_info['path'])
        try:
            if not os.path.exists(file_path_full):
                os.makedirs(os.path.dirname(file_path_full), exist_ok=True)
                with open(file_path_full, 'w', encoding='utf-8') as f:
                    f.write(file_info['default_content'])

            with open(file_path_full, 'r', encoding='utf-8') as f:
                content[key] = f.read()
        except Exception as e:
            flash(f'Error reading {file_info["path"]}: {e}', 'danger')
            return redirect(url_for('dashboard'))


    codemirror_theme_setting = AppSetting.query.filter_by(key='codemirror_theme').first()
    theme = codemirror_theme_setting.value if codemirror_theme_setting else 'default'

    return render_template('live_editor.html', site=site, content=content, theme=theme)

@app.route('/website/live_edit/save/<int:site_id>', methods=['POST'])
@login_required
def live_edit_save(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    data = request.json
    if not data:
        return jsonify({'status': 'danger', 'message': 'No data received.'}), 400

    files_to_save = {
        'index.html': data.get('html_content'),
        os.path.join('static', 'css', 'style.css'): data.get('css_content'),
        os.path.join('static', 'js', 'main.js'): data.get('js_content')
    }

    for file_path, content in files_to_save.items():
        if content is not None:
            full_path = get_safe_path(site, file_path)

            backup_result = create_file_backup(site, filename=os.path.basename(file_path), content=content)
            if backup_result['status'] == 'error':
                return jsonify(backup_result), 500

            try:
                with open(full_path, 'w', encoding='utf-8') as f:
                    f.write(content)
            except Exception as e:
                return jsonify({'status': 'danger', 'message': f'Error saving {file_path}: {e}'}), 500

    return jsonify({'status': 'success', 'message': 'All files saved successfully.'}), 200

@app.route('/website/live_edit/history/<int:site_id>/<string:filename>')
@login_required
def live_edit_history(site_id, filename):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    history_items = get_history_items(site, filename=filename)
    return jsonify(history_items)

@app.route('/website/live_edit/delete_backup/<int:site_id>', methods=['POST'])
@login_required
def delete_backup(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    backup_filename = request.form.get('backup_file')
    history_dir = get_history_path(site)
    backup_path_full = os.path.join(history_dir, backup_filename)

    # Security check: ensure the file is actually in the history folder
    if not os.path.realpath(backup_path_full).startswith(os.path.realpath(history_dir)):
        return jsonify({'status': 'danger', 'message': 'Invalid file path.'}), 400

    if not os.path.exists(backup_path_full):
        return jsonify({'status': 'warning', 'message': 'Backup file not found.'}), 404

    try:
        os.remove(backup_path_full)
        return jsonify({'status': 'success', 'message': f'Backup "{backup_filename.split(".")[1]}" deleted successfully.'})
    except Exception as e:
        return jsonify({'status': 'danger', 'message': f'Error deleting backup: {e}'}), 500


@app.route('/website/live_edit/restore/<int:site_id>', methods=['POST'])
@login_required
def live_edit_restore(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    backup_filename = request.form.get('backup_file')
    file_name = request.form.get('file_name')


    if not backup_filename or not file_name:
        return jsonify({'status': 'danger', 'message': 'No backup file specified.'}), 400

    history_dir = get_history_path(site)
    backup_path_full = os.path.join(history_dir, backup_filename)

    if file_name == 'index.html':
        target_file_path = get_safe_path(site, file_name)
    elif file_name == 'style.css':
        target_file_path = get_safe_path(site, os.path.join('static', 'css', 'style.css'))
    elif file_name == 'main.js':
        target_file_path = get_safe_path(site, os.path.join('static', 'js', 'main.js'))
    else:
        return jsonify({'status': 'danger', 'message': 'Invalid file name.'}), 400


    if not os.path.exists(backup_path_full):
        return jsonify({'status': 'danger', 'message': 'Backup file not found.'}), 404

    try:
        with open(backup_path_full, 'r', encoding='utf-8') as f:
            backup_content = f.read()
    except Exception as e:
        return jsonify({'status': 'danger', 'message': f'Error reading backup file: {e}'}), 500

    # 1. Check if content is already the same
    try:
        with open(target_file_path, 'r', encoding='utf-8') as f:
            current_content = f.read()
    except FileNotFoundError:
        # If the file doesn't exist, we can proceed with restoration
        current_content = ""
    except Exception as e:
         return jsonify({'status': 'danger', 'message': f'Error reading current file content for comparison: {e}'}), 500

    if calculate_content_hash(backup_content) == calculate_content_hash(current_content):
        # Return the content so the client can still update the editor UI if needed
        return jsonify({
            'status': 'warning',
            'message': f'The version from {backup_filename.split(".")[1]} is already the current file. Restore skipped.',
            'content': current_content
        }), 200

    # 2. If different, create a backup of the current file *before* overwriting it (allows undo)
    # The restore logic should now use the backup function which handles duplicate checking/replacement
    backup_result = create_file_backup(site, filename=file_name, content=current_content)
    if backup_result['status'] == 'error':
        return jsonify({'status': 'danger', 'message': f'Failed to create pre-restore backup: {backup_result["message"]}'}), 500

    # 3. Restore the selected backup
    try:
        shutil.copy2(backup_path_full, target_file_path)
        return jsonify({
            'status': 'success',
            'message': f'File "{file_name}" restored from backup "{backup_filename.split(".")[1]}".',
            'content': backup_content # Send new content back to client
        })
    except Exception as e:
        return jsonify({'status': 'danger', 'message': f'Error restoring file: {e}'}), 500

@app.route('/website/live_preview/<int:site_id>', defaults={'path': 'index.html'})
@app.route('/website/live_preview/<int:site_id>/<path:path>')
@login_required
def live_edit_preview(site_id, path):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    # When the iframe is first loaded, it will request index.html.
    # We serve the actual file content for the initial load.
    if path.lower() == 'index.html':
        base_path = get_site_base_path(site)
        file_path_full = os.path.join(base_path, 'index.html')
        try:
            with open(file_path_full, 'r', encoding='utf-8') as f:
                content = f.read()
            return content, 200, {'Content-Type': 'text/html'}
        except FileNotFoundError:
            # If index.html doesn't exist yet, return a blank page.
            # The editor content will populate it immediately.
            return "<html><head></head><body></body></html>", 200
        except Exception as e:
            return f"<h1>Error reading file: {e}</h1>", 500

    # For all other requests, serve the static file safely.
    safe_file_path = get_safe_path(site, path)

    if not os.path.isfile(safe_file_path):
        abort(404)

    directory = os.path.dirname(safe_file_path)
    filename = os.path.basename(safe_file_path)

    try:
        return send_from_directory(directory, filename)
    except Exception:
        abort(500)


# --- File Manager Routes (Modified) ---

@app.route('/files/<int:site_id>', defaults={'path': ''})
@app.route('/files/<int:site_id>/<path:path>')
@login_required
def manage_files(site_id, path):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    current_path_full = get_safe_path(site, path)
    if not os.path.isdir(current_path_full):
        flash('The requested path is not a directory.', 'danger')
        return redirect(url_for('manage_files', site_id=site_id, path=''))

    items = []
    # Exclude the 'history' folder from the file manager view
    for item_name in os.listdir(current_path_full):
        if item_name == 'history': continue
        item_path_full = os.path.join(current_path_full, item_name)
        item_rel_path = os.path.join(path, item_name)

        size = ''
        is_dir = os.path.isdir(item_path_full)
        if not is_dir:
            try:
                size_bytes = os.path.getsize(item_path_full)
                if size_bytes < 1024:
                    size = f"{size_bytes} B"
                elif size_bytes < 1024**2:
                    size = f"{size_bytes/1024:.1f} KB"
                else:
                    size = f"{size_bytes/1024**2:.1f} MB"
            except OSError:
                size = 'N/A'

        items.append({
            'name': item_name,
            'path': item_rel_path,
            'is_dir': is_dir,
            'size': size
        })

    items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
    parent_path = os.path.dirname(path) if path else ''

    return render_template('file_manager.html', site=site, items=items, current_path=path, parent_path=parent_path)


@app.route('/files/upload/<int:site_id>', methods=['POST'], defaults={'path': ''})
@app.route('/files/upload/<int:site_id>/<path:path>', methods=['POST'])
@login_required
def upload_file(site_id, path):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    if 'files' not in request.files:
        if request.is_json: # Handle XHR/fetch uploads without standard form data (like drag and drop)
            if not request.data:
                 return jsonify({'status': 'danger', 'message': 'No file data received.'}), 400
        else:
             flash('No file part', 'danger')
             return redirect(url_for('manage_files', site_id=site_id, path=path))

    uploaded_files = request.files.getlist('files')
    if not uploaded_files and not request.data:
        flash('No selected file', 'danger')
        return redirect(url_for('manage_files', site_id=site_id, path=path))

    dest_path = get_safe_path(site, path)
    uploaded_count = 0

    try:
        for file in uploaded_files:
            if file.filename:
                filename = secure_filename(file.filename)
                file.save(os.path.join(dest_path, filename))
                uploaded_count += 1

        # This part handles single file upload via XHR/fetch used in drag and drop
        if uploaded_count == 0 and request.data:
             filename = request.headers.get('X-File-Name')
             if filename:
                 filename = secure_filename(filename)
                 with open(os.path.join(dest_path, filename), 'wb') as f:
                     f.write(request.data)
                 uploaded_count += 1


    except Exception as e:
        # Return JSON error for XHR/fetch or flash message for traditional form
        if uploaded_files or request.data:
            return jsonify({'status': 'danger', 'message': f'Error uploading files: {e}'}), 500
        else:
            flash(f'Error uploading files: {e}', 'danger')
            return redirect(url_for('manage_files', site_id=site_id, path=path))


    if uploaded_files or request.data:
        return jsonify({'status': 'success', 'message': f'Successfully uploaded {uploaded_count} file(s).', 'refresh': True}), 200
    else:
        flash(f'Successfully uploaded {uploaded_count} file(s).', 'success')
        return redirect(url_for('manage_files', site_id=site_id, path=path))


@app.route('/files/download/<int:site_id>/<path:path>')
@login_required
def download_file(site_id, path):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    safe_path = get_safe_path(site, path)
    if not os.path.isfile(safe_path):
        abort(404)

    directory = os.path.dirname(safe_path)
    filename = os.path.basename(safe_path)

    return send_from_directory(directory, filename, as_attachment=True)


@app.route('/files/create_folder/<int:site_id>', methods=['POST'], defaults={'path': ''})
@app.route('/files/create_folder/<int:site_id>/<path:path>', methods=['POST'])
@login_required
def create_folder(site_id, path):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    folder_name = request.form.get('folder_name')
    if not folder_name or '..' in folder_name or '/' in folder_name:
        flash('Invalid folder name.', 'danger')
        return redirect(url_for('manage_files', site_id=site_id, path=path))

    dest_path = get_safe_path(site, path)
    new_folder_path = os.path.join(dest_path, folder_name)

    try:
        os.makedirs(new_folder_path)
        flash(f'Folder "{folder_name}" created.', 'success')
    except FileExistsError:
        flash(f'Folder "{folder_name}" already exists.', 'warning')
    except Exception as e:
        flash(f'Error creating folder: {e}', 'danger')

    return redirect(url_for('manage_files', site_id=site_id, path=path))


@app.route('/files/create_file/<int:site_id>', methods=['POST'], defaults={'path': ''})
@app.route('/files/create_file/<int:site_id>/<path:path>', methods=['POST'])
@login_required
def create_file(site_id, path):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    file_name = request.form.get('file_name')
    if not file_name or '..' in file_name or '/' in file_name or os.path.splitext(file_name)[1] == '':
        flash('Invalid file name. Must include a name and extension (e.g., index.html).', 'danger')
        return redirect(url_for('manage_files', site_id=site_id, path=path))

    dest_dir_path = get_safe_path(site, path)
    new_file_path = os.path.join(dest_dir_path, file_name)

    try:
        if os.path.exists(new_file_path):
            flash(f'File "{file_name}" already exists.', 'warning')
        else:
            # Create an empty file (or one with basic skeleton content if possible)
            # For now, we'll create a completely empty file.
            with open(new_file_path, 'w', encoding='utf-8') as f:
                # Optionally add a small content hint for common types
                if file_name.lower().endswith(('.html', '.htm')):
                    f.write("<!-- New HTML file created -->\n")
                elif file_name.lower().endswith('.css'):
                    f.write("/* New CSS file created */\n")
                elif file_name.lower().endswith('.js'):
                    f.write("// New JavaScript file created\n")
                else:
                    f.write("")
            flash(f'Empty file "{file_name}" created.', 'success')
    except Exception as e:
        flash(f'Error creating file: {e}', 'danger')

    return redirect(url_for('manage_files', site_id=site_id, path=path))


@app.route('/files/delete/<int:site_id>/<path:path>', methods=['POST'])
@login_required
def delete_item(site_id, path):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    item_path = get_safe_path(site, path)
    item_name = os.path.basename(path)
    current_dir = os.path.dirname(path)

    try:
        if os.path.isdir(item_path):
            shutil.rmtree(item_path)
            flash(f'Folder "{item_name}" deleted.', 'success')
        elif os.path.isfile(item_path):
            os.remove(item_path)
            flash(f'File "{item_name}" deleted.', 'success')
        else:
            flash('Item not found.', 'warning')
    except Exception as e:
        flash(f'Error deleting item: {e}', 'danger')

    return redirect(url_for('manage_files', site_id=site_id, path=current_dir))

@app.route('/files/edit/<int:site_id>/<path:path>')
@login_required
def edit_file(site_id, path):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    # Redirect index.html to the live editor
    if path.lower() == 'index.html':
        return redirect(url_for('live_edit', site_id=site_id))

    safe_path = get_safe_path(site, path)
    if not os.path.isfile(safe_path):
        flash('File not found.', 'danger')
        return redirect(url_for('manage_files', site_id=site_id))

    try:
        with open(safe_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        flash(f'Error reading file: {e}', 'danger')
        return redirect(url_for('manage_files', site_id=site_id, path=os.path.dirname(path)))

    codemirror_theme_setting = AppSetting.query.filter_by(key='codemirror_theme').first()
    theme = codemirror_theme_setting.value if codemirror_theme_setting else 'default'

    # Simple mode detection based on file extension
    extension = path.split('.')[-1].lower()
    modes = {
        'html': 'htmlmixed',
        'css': 'css',
        'js': 'javascript',
        'py': 'python',
        'xml': 'xml',
    }
    mode = modes.get(extension, 'text/plain')


    return render_template('edit_file.html', site=site, content=content, file_path=path, parent_path=os.path.dirname(path), theme=theme, mode=mode)

@app.route('/files/save/<int:site_id>/<path:path>', methods=['POST'])
@login_required
def save_file(site_id, path):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    # Redirect index.html save to the live editor save route
    if path.lower() == 'index.html':
        # Use 307 (Temporary Redirect) to preserve the POST method
        return redirect(url_for('live_edit_save', site_id=site_id), code=307)

    safe_path = get_safe_path(site, path)
    if not os.path.isfile(safe_path):
        flash('File not found.', 'danger')
        return redirect(url_for('manage_files', site_id=site_id))

    content = request.form.get('content')
    try:
        with open(safe_path, 'w', encoding='utf-8') as f:
            f.write(content)
        flash(f'File "{os.path.basename(path)}" saved successfully.', 'success')
    except Exception as e:
        flash(f'Error saving file: {e}', 'danger')

    return redirect(url_for('manage_files', site_id=site_id, path=os.path.dirname(path)))

@app.route('/files/copy/<int:site_id>/<path:path>')
@login_required
def copy_item(site_id, path):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    session['clipboard'] = {
        'action': 'copy',
        'source_path': path,
        'source_name': os.path.basename(path)
    }
    flash(f'"{os.path.basename(path)}" copied to clipboard.', 'info')
    return redirect(url_for('manage_files', site_id=site.id, path=os.path.dirname(path)))

@app.route('/files/cut/<int:site_id>/<path:path>')
@login_required
def cut_item(site_id, path):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    session['clipboard'] = {
        'action': 'cut',
        'source_path': path,
        'source_name': os.path.basename(path)
    }

    # Return JSON for XHR/fetch drag and drop handling
    if request.is_json or request.accept_mimetypes.accept_json:
        return jsonify({'status': 'info', 'message': f'"{os.path.basename(path)}" cut to clipboard (Drag/Drop ready).'}), 200

    flash(f'"{os.path.basename(path)}" cut to clipboard.', 'info')
    return redirect(url_for('manage_files', site_id=site.id, path=os.path.dirname(path)))

@app.route('/files/paste/<int:site_id>', methods=['GET', 'POST'], defaults={'dest_path': ''})
@app.route('/files/paste/<int:site_id>/<path:dest_path>', methods=['GET', 'POST'])
@login_required
def paste_item(site_id, dest_path):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    # 1. Determine if this is a standard paste or a drag-and-drop paste
    source_path_relative = None
    action = None
    is_drag_drop = False

    if request.method == 'POST' and request.is_json:
        # Drag and Drop Paste (POST with JSON payload)
        data = request.get_json()
        if data and 'source_path' in data and 'action' in data:
            source_path_relative = data['source_path']
            action = data['action']
            is_drag_drop = True

    if source_path_relative is None:
        # Standard Paste (GET/POST using session clipboard)
        clipboard = session.get('clipboard')
        if not clipboard:
            if is_drag_drop:
                 return jsonify({'status': 'warning', 'message': 'Clipboard is empty.'}), 400
            else:
                 flash('Clipboard is empty.', 'warning')
                 return redirect(url_for('manage_files', site_id=site.id, path=dest_path))

        source_path_relative = clipboard['source_path']
        action = clipboard['action']

    source_name = os.path.basename(source_path_relative)

    source_path_full = get_safe_path(site, source_path_relative)
    dest_path_full = get_safe_path(site, dest_path)
    dest_item_path = os.path.join(dest_path_full, source_name)

    # Basic checks
    if not os.path.exists(source_path_full):
        if is_drag_drop:
            session.pop('clipboard', None) # Clear session if file is gone
            return jsonify({'status': 'danger', 'message': f'Source item "{source_name}" not found.'}), 404
        else:
            flash(f'Source item "{source_name}" not found.', 'danger')
            session.pop('clipboard', None)
            return redirect(url_for('manage_files', site_id=site_id, path=dest_path))

    if os.path.isdir(dest_item_path) and os.path.isdir(source_path_full):
        if is_drag_drop:
             return jsonify({'status': 'warning', 'message': f'Folder "{source_name}" already exists in the destination.'}), 409
        else:
            flash(f'Folder "{source_name}" already exists in the destination.', 'warning')
            session.pop('clipboard', None)
            return redirect(url_for('manage_files', site_id=site_id, path=dest_path))

    # Self-copy/move check
    if source_path_full == dest_path_full or source_path_full == dest_item_path:
        session.pop('clipboard', None)
        if is_drag_drop:
            return jsonify({'status': 'warning', 'message': 'Cannot paste item into itself.'}), 400
        else:
            flash('Cannot paste item into itself.', 'warning')
            return redirect(url_for('manage_files', site_id=site.id, path=dest_path))

    try:
        if action == 'copy':
            if os.path.isdir(source_path_full):
                shutil.copytree(source_path_full, dest_item_path)
            else:
                shutil.copy2(source_path_full, dest_item_path)
            message = f'"{source_name}" copied to /{dest_path}.'
        elif action == 'cut':
            shutil.move(source_path_full, dest_item_path)
            message = f'"{source_name}" moved to /{dest_path}.'
        else:
            # Should not happen, but safe fallback
            raise ValueError("Invalid clipboard action.")

        session.pop('clipboard', None)

        if is_drag_drop:
            return jsonify({'status': 'success', 'message': message, 'refresh': True}), 200
        else:
            flash(message, 'success')
            return redirect(url_for('manage_files', site_id=site.id, path=dest_path))

    except Exception as e:
        session.pop('clipboard', None)
        error_message = f'Error pasting item: {e}'
        if is_drag_drop:
            return jsonify({'status': 'danger', 'message': error_message}), 500
        else:
            flash(error_message, 'danger')
            return redirect(url_for('manage_files', site_id=site.id, path=dest_path))

@app.route('/files/rename/<int:site_id>', methods=['POST'])
@login_required
def rename_item(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    old_path_relative = request.form.get('old_path')
    new_name = request.form.get('new_name')

    if not old_path_relative or not new_name or '..' in new_name or '/' in new_name:
        flash('Invalid request or name.', 'danger')
        return redirect(url_for('manage_files', site_id=site_id, path=os.path.dirname(old_path_relative) if old_path_relative else ''))

    old_path_full = get_safe_path(site, old_path_relative)
    new_path_full = get_safe_path(site, os.path.join(os.path.dirname(old_path_relative), new_name))

    try:
        os.rename(old_path_full, new_path_full)
        flash(f'Renamed "{os.path.basename(old_path_relative)}" to "{new_name}".', 'success')
    except Exception as e:
        flash(f'Error renaming item: {e}', 'danger')

    return redirect(url_for('manage_files', site_id=site_id, path=os.path.dirname(old_path_relative) if old_path_relative else ''))


@app.route('/files/clear_clipboard/<int:site_id>', methods=['GET'], defaults={'current_path': ''})
@app.route('/files/clear_clipboard/<int:site_id>/<path:current_path>', methods=['GET'])
@login_required
def clear_clipboard(site_id, current_path):
    session.pop('clipboard', None)
    return redirect(url_for('manage_files', site_id=site_id, path=current_path))

@app.route('/website/logs/<int:site_id>')
@login_required
def website_logs(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    site_path = get_site_base_path(site)
    log_file_path = os.path.join(site_path, 'logs.txt')

    if not os.path.exists(log_file_path):
        response = jsonify({
            'status': 'warning',
            'logs': [f"Log file not found. Please ensure the website '{site.name}' is running."],
            'name': site.name
        })
        response.headers['Content-Type'] = 'application/json'
        return response, 200

    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Read all lines
            lines = f.readlines()

            # Get the last 1000 lines, ensuring we always return a list of lines
            log_content = [line.strip() for line in lines[-1000:]]

        response = jsonify({
            'status': 'success',
            'logs': log_content,
            'name': site.name
        })
        # Explicitly set content type for robustness
        response.headers['Content-Type'] = 'application/json'
        return response, 200

    except Exception as e:
        # If any internal error occurs, ensure we return valid JSON with a clear error message
        response = jsonify({
            'status': 'danger',
            'logs': [f"Error reading log file: {e}"],
            'name': site.name
        })
        response.headers['Content-Type'] = 'application/json'
        return response, 500

@app.route('/how-to-develop')
@login_required
def how_to_develop():
    return render_template('how_to_develop.html', title='How to Develop')

# -----------------------------------------------------------------------------
# App Startup
# -----------------------------------------------------------------------------
def init_app_on_start():
    """Initializes the database and folders on startup."""
    with app.app_context():
        db.create_all()
        if not os.path.exists(config.Config.WEBSITES_BASE_FOLDER):
            os.makedirs(config.Config.WEBSITES_BASE_FOLDER)
            print(f"Created websites base folder at: {config.Config.WEBSITES_BASE_FOLDER}")

        if not AppSetting.query.filter_by(key='allow_registration').first():
            db.session.add(AppSetting(key='allow_registration', value='true'))
            db.session.commit()
            print("Initialized registration setting.")

        print("Database initialized and checked.")

def start_autostart_websites():
    """Starts all websites that have the autostart flag set to True."""
    with app.app_context():
        autostart_sites = Website.query.filter_by(autostart=True).all()
        if not autostart_sites:
            print("No websites marked for autostart.")
            return

        print(f"Found {len(autostart_sites)} websites to autostart...")
        for site in autostart_sites:
            print(f"Attempting to autostart '{site.name}' on port {site.port}...")

            # Ensure log file exists before starting the process
            site_path = get_site_base_path(site)
            log_file_path = os.path.join(site_path, 'logs.txt')
            if not os.path.exists(log_file_path):
                try:
                    os.makedirs(site_path, exist_ok=True)
                    with open(log_file_path, 'w') as f:
                        f.write(f"--- Log file created during autostart at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                except Exception as e:
                    print(f"Error creating log file for autostart site {site.name}: {e}")
                    # Skip starting the site if logging setup fails
                    continue

            process = Process(target=websites.run_website, args=(site_path, site.port, site.id))
            process.start()

            site.process_id = process.pid
            running_processes[site.id] = process
            db.session.commit()
            print(f"Successfully started '{site.name}' with PID {process.pid}.")


if __name__ == '__main__':
    init_app_on_start()
    start_autostart_websites()
    try:
        app.run(host='0.0.0.0', debug=True, threaded=True, use_reloader=False)
    finally:
        cleanup_processes()
