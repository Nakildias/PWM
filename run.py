import os
import subprocess
import sys
import shutil
from multiprocessing import Process, active_children
from flask import Flask, render_template, redirect, url_for, flash, session, request, send_from_directory, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, NumberRange
from datetime import date, datetime
import config
import websites

# Keep track of running processes
running_processes = {}

# -----------------------------------------------------------------------------
# App Initialization
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(config.Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
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

    __table_args__ = (db.UniqueConstraint('user_id', 'name', name='_user_id_name_uc'),)
    visitors = db.relationship('Visitor', backref='website', lazy=True, cascade="all, delete-orphan")

class Visitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False)
    date = db.Column(db.Date, nullable=False, default=lambda: date.today())
    daily_visits = db.Column(db.Integer, default=1)

    __table_args__ = (db.UniqueConstraint('website_id', 'date', name='_website_id_date_uc'),)

class DailyUniqueVisitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False) # IPv4 or IPv6
    date = db.Column(db.Date, nullable=False, default=lambda: date.today())

    __table_args__ = (db.UniqueConstraint('website_id', 'ip_address', 'date', name='_website_ip_date_uc'),)

class VisitLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    country_code = db.Column(db.String(2), nullable=True)
    country_name = db.Column(db.String(100), nullable=True)

    __table_args__ = (db.Index('idx_website_timestamp', 'website_id', 'timestamp'),)

class AppSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(100), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# -----------------------------------------------------------------------------
# Forms
# -----------------------------------------------------------------------------
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

def get_daily_visits(site_id):
    today = date.today()
    visitor_entry = Visitor.query.filter_by(website_id=site_id, date=today).first()
    return visitor_entry.daily_visits if visitor_entry else 0

def get_site_base_path(site):
    """Returns the base directory path for a given site."""
    return os.path.join(config.Config.WEBSITES_BASE_FOLDER, str(site.user_id), site.name)

def get_safe_path(site, unsafe_path=''):
    """
    Constructs a safe, absolute path for a file or directory within a site's folder.
    Prevents directory traversal attacks.
    """
    base_path = get_site_base_path(site)
    full_path = os.path.realpath(os.path.join(base_path, unsafe_path))

    if os.path.commonprefix([full_path, base_path]) != base_path:
        abort(403) # Forbidden

    return full_path


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
    daily_visits = {site.id: get_daily_visits(site.id) for site in user_websites}
    return render_template('dashboard.html', title='Dashboard', sites=user_websites, form=form, running_processes=running_processes, daily_visits=daily_visits)

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
        os.makedirs(site_path, exist_ok=True)

        with open(os.path.join(site_path, 'index.html'), 'w') as f:
            f.write(f'<h1>Welcome to {new_site.name}!</h1>')

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

# FIX: The missing route is now added, resolving the BuildError.
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

@app.route('/website/edit/<int:site_id>', methods=['GET', 'POST'])
@login_required
def edit_website(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    form = EditWebsiteForm(original_name=site.name, original_port=site.port, user_id=current_user.id)

    if form.validate_on_submit():
        original_site_path = get_site_base_path(site)
        site.name = form.name.data
        site.port = form.port.data
        db.session.commit()

        new_site_path = get_site_base_path(site)
        if original_site_path != new_site_path:
            try:
                os.rename(original_site_path, new_site_path)
            except OSError as e:
                flash(f'Error renaming website folder: {e}', 'danger')
                # Consider what to do here - maybe roll back the name change in the DB
                # For now, we'll just flash the error.

        flash(f'Website "{site.name}" updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    form.name.data = site.name
    form.port.data = site.port
    return render_template('edit_website.html', form=form, site=site)

# --- File Manager Routes ---

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
    for item_name in os.listdir(current_path_full):
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

    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('manage_files', site_id=site_id, path=path))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('manage_files', site_id=site_id, path=path))

    if file:
        filename = secure_filename(file.filename)
        dest_path = get_safe_path(site, path)
        file.save(os.path.join(dest_path, filename))
        flash(f'File "{filename}" uploaded successfully.', 'success')

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
    return redirect(url_for('manage_files', site_id=site_id, path=os.path.dirname(path)))

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
    flash(f'"{os.path.basename(path)}" cut to clipboard.', 'info')
    return redirect(url_for('manage_files', site_id=site_id, path=os.path.dirname(path)))

@app.route('/files/paste/<int:site_id>', methods=['GET'], defaults={'dest_path': ''})
@app.route('/files/paste/<int:site_id>/<path:dest_path>', methods=['GET'])
@login_required
def paste_item(site_id, dest_path):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    clipboard = session.get('clipboard')
    if not clipboard:
        flash('Clipboard is empty.', 'warning')
        return redirect(url_for('manage_files', site_id=site.id, path=dest_path))

    source_path_full = get_safe_path(site, clipboard['source_path'])
    dest_path_full = get_safe_path(site, dest_path)
    dest_item_path = os.path.join(dest_path_full, clipboard['source_name'])

    if source_path_full == dest_path_full or source_path_full == dest_item_path:
        session.pop('clipboard', None)
        flash('Cannot paste item into itself.', 'warning')
        return redirect(url_for('manage_files', site_id=site_id, path=dest_path))

    try:
        action = clipboard['action']
        if action == 'copy':
            if os.path.isdir(source_path_full):
                shutil.copytree(source_path_full, dest_item_path)
            else:
                shutil.copy2(source_path_full, dest_item_path)
            flash(f'"{clipboard["source_name"]}" copied.', 'success')
        elif action == 'cut':
            shutil.move(source_path_full, dest_item_path)
            flash(f'"{clipboard["source_name"]}" moved.', 'success')

        session.pop('clipboard', None)
    except Exception as e:
        flash(f'Error pasting item: {e}', 'danger')

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

@app.route('/website/stats/<int:site_id>')
@login_required
def website_stats(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    today = date.today()
    
    # Monthly and Yearly data
    monthly_visits = db.session.query(
        db.func.strftime('%Y-%m', Visitor.date).label('month'),
        db.func.sum(Visitor.daily_visits).label('visits')
    ).filter(
        Visitor.website_id == site_id,
        db.func.strftime('%Y', Visitor.date) == str(today.year)
    ).group_by('month').order_by('month').all()

    yearly_visits = db.session.query(
        db.func.strftime('%Y', Visitor.date).label('year'),
        db.func.sum(Visitor.daily_visits).label('visits')
    ).filter(
        Visitor.website_id == site_id
    ).group_by('year').order_by('year').all()

    monthly_labels = [row.month for row in monthly_visits]
    monthly_data = [row.visits for row in monthly_visits]
    
    yearly_labels = [row.year for row in yearly_visits]
    yearly_data = [row.visits for row in yearly_visits]

    return jsonify({
        'monthly': {
            'labels': monthly_labels,
            'data': monthly_data
        },
        'yearly': {
            'labels': yearly_labels,
            'data': yearly_data
        }
    })

@app.route('/website/stats/<int:site_id>/hourly')
@login_required
def website_hourly_stats(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    today = date.today()
    hourly_visits = db.session.query(
        db.func.strftime('%H', VisitLog.timestamp).label('hour'),
        db.func.count(VisitLog.id).label('visits')
    ).filter(
        VisitLog.website_id == site_id,
        db.func.date(VisitLog.timestamp) == today
    ).group_by('hour').order_by('hour').all()

    hourly_labels = [f'{int(row.hour):02d}:00' for row in hourly_visits]
    hourly_data = [row.visits for row in hourly_visits]

    return jsonify({
        'labels': hourly_labels,
        'data': hourly_data
    })

@app.route('/website/stats/<int:site_id>/daily_unique')
@login_required
def website_daily_unique_stats(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    daily_unique_visits = db.session.query(
        db.func.strftime('%Y-%m-%d', DailyUniqueVisitor.date).label('day'),
        db.func.count(DailyUniqueVisitor.id).label('unique_visits')
    ).filter(
        DailyUniqueVisitor.website_id == site_id
    ).group_by('day').order_by('day').all()

    daily_labels = [row.day for row in daily_unique_visits]
    daily_data = [row.unique_visits for row in daily_unique_visits]

    return jsonify({
        'labels': daily_labels,
        'data': daily_data
    })

@app.route('/website/stats/<int:site_id>/logs')
@login_required
def website_visit_logs(site_id):
    site = db.get_or_404(Website, site_id)
    if site.owner != current_user:
        abort(403)

    # Fetch recent 100 visit logs for simplicity, order by timestamp descending
    visit_logs = VisitLog.query.filter_by(website_id=site_id).order_by(VisitLog.timestamp.desc()).limit(100).all()

    logs_data = []
    for log in visit_logs:
        logs_data.append({
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'ip_address': log.ip_address,
            'country_code': log.country_code,
            'country_name': log.country_name
        })
    return jsonify(logs_data)

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
            site_path = get_site_base_path(site)
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
