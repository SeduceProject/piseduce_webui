from api.tool import decrypt_password
from database.connector import open_session, close_session
from database.tables import Smtp, User
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask_login import current_user, login_user, login_required, logout_user
from lib.config_loader import load_config
from werkzeug.security import generate_password_hash, check_password_hash
import flask, logging, random, smtplib, string


b_login = flask.Blueprint("login", __name__, template_folder="templates/")
TOKEN_LENGTH = 50


@b_login.route("/")
def root():
    return flask.redirect("/login")


@b_login.route("/login")
def login():
    if current_user.is_authenticated:
        return flask.redirect("/user/reserve")
    else:
        return flask.render_template("login.html")


@b_login.route("/login-post", methods=["POST"])
def login_post():
    if current_user.is_authenticated:
        return flask.redirect("/user/reserve")
    form_data = flask.request.form
    authenticated = False
    if len(form_data["email"]) > 0 and len(form_data["pwd"]) > 0:
        db = open_session()
        user = db.query(User).filter_by(email = form_data["email"]).first()
        if user is not None and user.is_authorized:
            if check_password_hash(user.password, form_data["pwd"]):
                authenticated = True
                login_user(user, remember=True)
            else:
                msg="Wrong email or password"
        else:
            msg = "User is not authorized to login"
        close_session(db)
    else:
        msg = "Missing parameters: 'email' or 'pwd'"
    if authenticated:
        return flask.redirect("/user/reserve")
    else:
        return flask.redirect("/login?msg=%s" % msg)


@b_login.route("/signup")
def signup():
    if current_user.is_authenticated:
        return flask.redirect("/user/reserve")
    else:
        return flask.render_template("signup.html")



def send_confirmation_email(user_account, smtp, public_address):
    token = "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(TOKEN_LENGTH))
    # Save the token to the database
    email_sent = False
    try:
        user_account.email_token = token
        # Send the configuration email
        msg = MIMEMultipart()
        msg['From'] = smtp.account
        msg['To'] = user_account.email
        msg['Subject'] = "Please confirm your email"
        body = """Hello,
    Thanks for creating an account on the PiSeduce Resource Manager.
    In order to proceed with your account creation, please confirm your email by browsing on the following link:
    %s/confirm_email/%s
    Best Regards,
    Seduce administrators
    """ % (public_address, token)
        msg.attach(MIMEText(body, 'plain'))
        # Configure the smtp server
        smtp_server = smtplib.SMTP(smtp.server_address, smtp.server_port)
        smtp_server.ehlo()
        smtp_server.starttls()
        smtp_server.ehlo()
        logging.warning(decrypt_password(smtp.password))
        smtp_server.login(smtp.account, decrypt_password(smtp.password))
        text = msg.as_string()
        smtp_server.sendmail(smtp.account, user_account.email, text)
        smtp_server.quit()
        return True
    except:
        logging.exception("error while sending the confirmation email:")
    return False



@b_login.route("/signup-post", methods=["POST"])
def signup_post():
    if current_user.is_authenticated:
        return flask.redirect("/user/reserve")
    msg = ""
    user_created = False
    form_data = flask.request.form
    if len(form_data["email"]) > 0 and len(form_data["pwd"]) > 0 and \
        len(form_data["confirm_pwd"]) > 0:
        db = open_session()
        email = form_data['email']
        # Retrieve the email filter
        efilter = db.query(Smtp).filter(Smtp.enabled == True).first()
        if efilter is not None and len(efilter.email_filter) > 0:
            whitelist = efilter.email_filter.split(",")
            if email.split("@")[1] not in whitelist:
                msg = "Email domain name is not authorized. Please contact the administrator."
        if len(msg) == 0:
            user = db.query(User).filter_by(email=email).first()
            if user is not None:
                msg = "can not sign up: email already exists"
        if len(msg) == 0:
            password = form_data['pwd']
            confirm_pwd = form_data['confirm_pwd']
            user_created = False
            if password == confirm_pwd:
                new_user = User(email=email, password=generate_password_hash(password, method='sha256'))
                db.add(new_user)
                user_created = True
                msg = "Your account must be confirmed before the first login"
                if efilter is not None:
                    # Send the confirmation email
                    app_conf = load_config()
                    base_url = flask.request.url_root
                    if "public_address" in app_conf and len(app_conf["public_address"]) > 0:
                        base_url = app_conf["public_address"]
                    if not send_confirmation_email(new_user, efilter, base_url):
                        msg = "Your account is created but the confirmation email is not sent. Please contact your administrator."
            else:
                msg = "'Password' and 'Confirm Password' does not match"
        close_session(db)
    else:
        msg = "Missing parameters: 'email' or 'pwd' or 'confirm_pwd'"
    if user_created:
        return flask.redirect("/login?msg=%s" % msg)
    elif len(msg) > 0:
        return flask.redirect("/signup?msg=%s" % msg)
    else:
        return flask.redirect("/signup?msg=Sign up failure")


@b_login.route("/confirm_email/<token>")
def confirm_email_post(token):
    db = open_session()
    # Retrieve the token
    user = db.query(User).filter(User.email_token == token).first()
    if user is None or len(user.email_token) != TOKEN_LENGTH:
        msg = "Unknwown token error: please contact your administrator."
        logging.error(msg)
    else:
        user.is_authorized = True
        user.email_token = "consumed"
        msg = "Email is confirmed. You can log in!"
    close_session(db)
    return flask.redirect("/login?msg=%s" % msg)


@b_login.route('/logout')
@login_required
def logout():
    logout_user()
    return flask.redirect("/login?msg=You are logged off")
