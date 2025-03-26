import string
import os
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
login_manager = LoginManager()
login_manager.init_app(app)

# CREATE DATABASE


class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CREATE TABLE IN DB


class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()

def password_check(password):

    special_chars = list(string.punctuation)

    if len(password) < 6:
        return False
    elif not any(char.isdigit() for char in password):
        return False
    elif not any(char.isupper() for char in password):
        return False
    elif not any(char.islower() for char in password):
        return False
    elif not any(char in special_chars for char in password):
        return False
    else:
        return True


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('secrets'))

    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        
        user_exist = db.session.query(db.exists().where(User.name == name)).scalar()
        email_exist = db.session.query(db.exists().where(User.email == email)).scalar()
        
        if user_exist or email_exist:
            flash("Username or password exists")
            return redirect(url_for("register"))
        
        if not password_check(password):
            flash("Password need to be:\nLonger than 6 characters\nContains low letter, great letter, digit and special character")
            return redirect(url_for("register"))

        pass_hash = generate_password_hash(password, method="pbkdf2", salt_length=8)
        print(pass_hash)

        user = User(name=name, email=email, password=pass_hash)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return render_template('secrets.html', name=name)

    return render_template("register.html")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("secrets"))
    
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not db.session.query(db.exists().where(User.email == email)).scalar():
            flash("The email does not exists, please try again later.")
            return redirect(url_for("login"))

        user = User.query.filter_by(email=email).first()


        if user is not None:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for("secrets"))
            else:
                flash("Password is incorrect.")
                return redirect(url_for("login"))
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/download/<path:filename>', methods=["GET", "POST"])
@login_required
def download(filename):
    directory = os.path.join(app.root_path, "static//files")
    return send_from_directory(directory, filename)


@app.route('/upload', methods=['POST'])
@login_required
def upload():
    directory = os.path.join(app.root_path, "static//files")
    allowed_extensions = {'txt', 'jpg', 'png', 'pdf', 'docx'}

    if request.method == "POST":
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(directory, filename))
            return redirect(url_for('secrets', name=filename))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
