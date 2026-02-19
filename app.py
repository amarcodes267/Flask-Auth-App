from flask import Flask, render_template, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import os
import re
from functools import wraps

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = os.environ.get("SECRET_KEY", "super_secret_key")

db = SQLAlchemy(app)


# 🔐 Login Required Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            flash("Please login first!", "warning")
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(
            password.encode('utf-8'),
            self.password.encode('utf-8')
        )


with app.app_context():
    db.create_all()


@app.route("/")
def index():
    return render_template("index.html")


# ✅ REGISTER ROUTE WITH EMAIL FORMAT VALIDATION
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        # Name validation
        if not name:
            flash("Name is required!", "danger")
            return render_template("register.html")

        # Email validation
        if not email:
            flash("Email is required!", "danger")
            return render_template("register.html")

        # ✅ Email format check
        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_pattern, email):
            flash("Invalid email format!", "danger")
            return render_template("register.html")

        # Password validation
        if not password:
            flash("Password is required!", "danger")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must be at least 6 characters!", "danger")
            return render_template("register.html")

        # Email uniqueness
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered !! Try With Another Email ..", "danger")
            return render_template("register.html")

        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please login.", "success")
        return redirect('/login')

    return render_template("register.html")


# LOGIN
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash("All fields are required!", "danger")
            return render_template("login.html")

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['email'] = user.email
            session['name'] = user.name
            flash("Login successful!", "success")
            return redirect('/dashboard')
        else:
            flash("Invalid email or password!", "danger")

    return render_template("login.html")


# DASHBOARD
@app.route("/dashboard")
@login_required
def dashboard():
    user = User.query.filter_by(email=session['email']).first()
    return render_template("dashboard.html", user=user)


# ✅ DELETE ACCOUNT FEATURE
@app.route("/delete_account", methods=['POST'])
@login_required
def delete_account():
    user = User.query.filter_by(email=session['email']).first()

    if user:
        db.session.delete(user)
        db.session.commit()

        session.clear()
        flash("Your account has been deleted successfully.", "info")
        return redirect('/')

    flash("Something went wrong.", "danger")
    return redirect('/dashboard')


# LOGOUT
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully!", "info")
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
