from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'gfgfg bfhhfrh'  # For session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

@app.route('/')
def home():
    return render_template('login.html')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        # Check if the email already exists
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash("Email already exists!", 'danger')
            return redirect(url_for('register'))

        # Create new user
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful!", 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id  # Store user ID in session
            # Check if the user is admin
            if user.email == 'vkayz@gmail.com':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed! Account does not exist or incorrect credentials.", 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

# Dashboard route (User dashboard)
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

# Admin dashboard route (for Admin to manage users)
@app.route('/admin-dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user.email != 'vkayz@gmail.com':
        return redirect(url_for('dashboard'))  # Redirect non-admin users to their dashboard
    
    # Get all users (excluding the admin user)
    users = User.query.filter(User.email != 'vkayz@gmail.com').all()
    return render_template('admin_dashboard.html', user=user, users=users)

# Delete user route (Admin only)
@app.route('/delete_user/<int:user_id>', methods=['GET'])
def delete_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user.email != 'vkayz@gmail.com':
        return redirect(url_for('dashboard'))  # Redirect non-admin users to their dashboard
    
    # Find user by ID and delete
    user_to_delete = User.query.get(user_id)
    if user_to_delete:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User deleted successfully!", 'success')
    return redirect(url_for('admin_dashboard'))

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove user from session
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
     db.create_all()  # Ensure the database and tables are created
    app.run(debug=True)
