from flask import Flask, render_template, session, redirect, jsonify
from config import ApplicationConfig
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, Email
from flask_bcrypt import Bcrypt
from models import db, User
from logger import logger

# Initialize the app
app = Flask(__name__)

# Set the configurations from external object
app.config.from_object(ApplicationConfig)

# Initialize the password hash object
bcrypt = Bcrypt(app)

# Initialize the Database
db.init_app(app)
with app.app_context():
    db.create_all()
# Initialize the migrator
migrate = Migrate(app, db)


"""
Forms
"""
class LoginForm(FlaskForm):
    usermail = EmailField("Email Address", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField()


class RegisterForm(FlaskForm):
    usermail = EmailField("Email Address", validators=[DataRequired(), Email()])
    username = StringField("Your name", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField()


"""
API Endpoints
"""
@app.route('/', methods=['GET', 'POST'])
def index():

    # If we're not logged in then goto the users page
    if session.get("user_id") is None:
        return redirect("/login")


    # If we don't have any url, then just show the base index page
    return render_template("index.html")


"""
Login and Sign-up endpoints
"""
@app.route("/register", methods=["GET", "POST"])
def register_user():
    email = None
    username = None
    password = None

    form = RegisterForm()

    if form.validate_on_submit():
        email = form.usermail.data
        username = form.username.data
        password = form.password.data

    # Check if the user already exists?
    user_exists = User.query.filter_by(email=email).first() is not None

    if user_exists:
        logger.error(f"User already exists, Email: {email}, Username: {username}")
        # User already exists
        return render_template("/user/register.html", form=form, error={'code': 409})

    # Else create a new user
    if email is not None and username is not None and password is not None:
        hashed_passwd = bcrypt.generate_password_hash(password)
        # Create a new user and add to the Database
        new_user = User(email=email, password=hashed_passwd, username=username)
        db.session.add(new_user)
        # Save the changes permanently
        db.session.commit()

        # Log the user in on new registration
        session["user_id"] = new_user.id

        logger.info(f"User logged in, Email: {email}, Username: {username}")

        # Redirect to homepage
        return redirect("/")

    return render_template("/user/register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login_user():
    usermail = None
    passwd = None

    # Initialize the form
    form = LoginForm()

    # If the form is validated successfully
    if form.validate_on_submit():
        usermail = form.usermail.data
        passwd = form.password.data

        # Reset these fields
        form.password.data = ""

    # If we have user-mail and password, then check if this user exists?
    user = User.query.filter_by(email=usermail).first()

    if user is None and (usermail is not None and passwd is not None):
        # Then return an unauthorized response
        logger.error(f"User not found for email={usermail}")
        return render_template("user/login.html", form=form, error={'code': 404})

    if user is not None:
        if not bcrypt.check_password_hash(user.password, passwd):
            # Unauthorized access
            logger.error(f"Password is wrong for email={usermail}")
            return render_template(
                "user/login.html", form=form, error={'code': 401}
            )

        # Set the session
        session["user_id"] = user.id
        # Redirect to the home page
        return redirect("/")

    # Redirect to home page
    return render_template("user/login.html", form=form)


@app.route("/logout", methods=["GET", "POST"])
def logout_user():
    # Logout the user
    session.pop("user_id", None)
    # Redirect to the home page
    return redirect("/")


if __name__ == '__main__':
    app.run(debug=True)