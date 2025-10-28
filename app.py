import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# --- App and Database Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a-very-secret-key-change-this' # Change this to a random string
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///iedc.db' # This creates a database file named iedc.db
app.config['UPLOAD_FOLDER'] = 'static/uploads' # Folder to store uploaded images
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redirect to login page if user is not logged in

# --- Database Models (Our Tables) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False) # 'student', 'sub-admin', 'admin'
    department = db.Column(db.String(100)) # e.g., 'Computer Science'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_filename = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default='pending') # 'pending', 'approved_by_sub', 'rejected'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes (The Web Pages) ---

# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            # Redirect based on role
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'sub-admin':
                return redirect(url_for('sub_admin_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Dashboards ---

@app.route('/')
@app.route('/student_dashboard', methods=['GET', 'POST'])
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Check if a file was uploaded
        if 'image' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['image']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            new_submission = Submission(
                image_filename=filename,
                description=request.form['description'],
                user_id=current_user.id,
                department=current_user.department
            )
            db.session.add(new_submission)
            db.session.commit()
            flash('Image uploaded successfully! Awaiting review.')
            return redirect(url_for('student_dashboard'))

    return render_template('student.html')


@app.route('/sub_admin_dashboard')
@login_required
def sub_admin_dashboard():
    if current_user.role != 'sub-admin':
        return redirect(url_for('login'))
    
    # Get pending submissions ONLY from the sub-admin's department
    pending_submissions = Submission.query.filter_by(
        department=current_user.department, 
        status='pending'
    ).all()
    return render_template('sub_admin.html', submissions=pending_submissions)


@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    
    # Get submissions approved by sub-admins from ALL departments
    approved_submissions = Submission.query.filter_by(status='approved_by_sub').all()
    return render_template('admin.html', submissions=approved_submissions)

# --- Actions for Sub-Admin ---

@app.route('/approve/<int:submission_id>')
@login_required
def approve_submission(submission_id):
    if current_user.role != 'sub-admin':
        return redirect(url_for('login'))
    
    submission = Submission.query.get_or_404(submission_id)
    # Security check: make sure sub-admin can only approve for their own department
    if submission.department == current_user.department:
        submission.status = 'approved_by_sub'
        db.session.commit()
        flash('Submission approved and forwarded to main admin.')
    else:
        flash('You do not have permission to do this.')
    return redirect(url_for('sub_admin_dashboard'))


# This is the main entry point to run the app
if __name__ == '__main__':
    with app.app_context():
        # Create folders if they don't exist
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        db.create_all() # This creates the database and tables
    app.run(debug=True) # debug=True helps you see errors while developing
    # --- Add this entire block to the BOTTOM of your app.py file ---

@app.cli.command("init-db")
def init_db_command():
    """Clears the existing data and creates new tables and users."""
    db.create_all()
    
    # Check if admin user already exists
    if User.query.filter_by(username='admin').first() is None:
        print("Creating default users...")
        # Create Admin
        admin_user = User(username='admin', role='admin', department='College')
        admin_user.set_password('admin123')
        db.session.add(admin_user)

        # Create Sub-Admin (Teacher)
        teacher_user = User(username='teacher_cs', role='sub-admin', department='Computer Science')
        teacher_user.set_password('teacher123')
        db.session.add(teacher_user)

        # Create Student
        student_user = User(username='student_cs', role='student', department='Computer Science')
        student_user.set_password('student123')
        db.session.add(student_user)

        db.session.commit()
        print("Default users created.")
    else:
        print("Users already exist.")

    print("Initialized the database.")