#---- Imports ----#


import os
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, request, make_response, url_for
from sqlalchemy import Text, Numeric, Integer, create_engine, MetaData, Column, Table  # For DB interactions.
from sqlalchemy.orm import sessionmaker
import argon2 # For hashing passwords.
from authlib.integrations.flask_client import OAuth # For authorization with Google.
from datetime import datetime, timedelta


#---- Password Hasher initialization ----#


hasher = argon2.PasswordHasher(  # Hashing user's password.

    time_cost=3,  # Number of iterations.
    memory_cost=102400,  # 100 Mb in KiB.
    parallelism=8,  # Number of parallel threads.
    hash_len=32,  # Hash's length in bytes.
    type=argon2.Type.ID, # Using Argon2id version. (Most efficient, since it combines benefits of both Argon2d and Argon2i)

)


#---- App And Database Initialization ----#


app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

# Loading .env

load_dotenv()

# PostgreSQL arguments:

user = os.getenv("DB_USERNAME")
password = os.getenv("DB_PASSWORD")
host = os.getenv("DB_HOST")
port = os.getenv("DB_PORT")
name = os.getenv("DB_NAME")

# Declaring the URL of the Database:

DATABASE_URL = f"postgresql://{user}:{password}@{host}:{port}/{name}"

# Engine Declaration:

engine = create_engine(DATABASE_URL)


# This is done in order to have a UserMixin inheritance from flask-login, which, in turn, will let me track whether the user's logged in.

meta_data_obj = MetaData() # Where all the tables and columns will be stored.


# Main DB tables:

# There will be 2 main tables: one will contain all the data about the customers, and the second one - about the products.

# PLS PLS PLS PLS PLS KEEP EVERY SINGLE COLUMN NAME WITHOUT SPACEBARS!!

customer_table = Table(

    "Customer Data",

    meta_data_obj,

    Column("ID", Integer, primary_key=True, autoincrement=True),
    Column("FirstName", Text, nullable=False, unique=False),
    Column("LastName", Text, nullable=False, unique=False),
    Column("Email", Text, nullable=False, unique=True, index=True),
    Column("Password", Text, nullable=False),
    Column("Liked", Integer, nullable=True), # Will store the amount of liked items the user has.
    Column("InCart", Integer, nullable=True),
    Column("ProfilePicture", Text, nullable=True),
    #Column("UserVideos") - for user's videos.
    #Column("2FA", bool, nullable=False) - for the two-factor authentication.

)

product_table = Table(

    "Product Data",

    meta_data_obj,

Column("ID", Integer, primary_key=True, autoincrement=True),
    Column("Name", Text, nullable=False),
    Column("Rating", Numeric, nullable=False),
    Column("Price", Numeric, nullable=False),
    Column("Amount", Integer, nullable=False),
    Column("Tags", Text, nullable=False, index=True),
    Column("Reviews", Text, nullable=False),
    Column("Description", Text, nullable=False),
    Column("Images", Text, nullable=False),

)

# TODO: I'll probably have to add a third DB, called "Customer_Products", where I'll specify the user ID and the respective ID's of the products he/she has in their carts/liked.

# TODO: for late-stage development - create a seed data for the database using bulk_insert()

# In order to let all the users have a data by default when forking my project.

# I think i'll have like 4 products per category, so that index page and search will function properly.

# Hence, it'll prolly has 3 columns. One-to-many relationship.



# Creating all the tables and initiating session.

meta_data_obj.create_all(engine)

Session_db = sessionmaker(bind=engine)

session_db = Session_db()

# session_db.bulk_insert_mappings() !!!!!!!!!!!!!!!!!


# Cookie Management.


def is_registered(): # Checks if the user's registered.

    # Returns the cookie.

    # If the cookie hasn't been set - returns None.

    # Else - returns the ID of the user.

    saved_cookie = request.cookies.get("saved_cookies")

    return saved_cookie


def email_query(email: str): # In order to query the user by their email.

    return session_db.query(customer_table).where(customer_table.c.Email == email).first()


#---- Initializing Oauth ----#


oauth = OAuth(app) # Initializing the object. (Will do more with it in /google path).

GOOGLE_CLIENT_ID = os.getenv("CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("CLIENT_SECRET")

CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'

google = oauth.register(  # Registering with Google Cloud credentials.

    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url=CONF_URL,
    client_kwargs={

        "scope": "openid profile email",  # I.e., what information will the server request from the user.

    },

)


#---- Website Functionality ----#


@app.route("/")
def main_page(): # Speaks for itself.

    has_cookies = is_registered() # Checks user's browser for cookies. The HTML pages will change depending on the content of the variable.

    if has_cookies:

        user_data = session_db.query(customer_table).where(customer_table.c.ID == has_cookies).first() # Fetching all the data about the user, utilizing his ID.

    else:

        user_data = None # In case has_cookies is None - then pass in the user's data as None too.


    return render_template(

                            "index.html",

                           registered=has_cookies,

                           user_data=user_data,

                           liked_products=["A","A","A","A","A","A","A","A","A","A","A"],

                           in_cart_products=["B","B","B","B","B","B","B","B"],

                           categories=["Anime", "Books", "Music"]

                           )


#---- Log-in Mechanism ----#


@app.route("/login", methods=["GET", "POST"])
def login_page():

    if is_registered():  # If the user's trying to log in while already having an account.

        return redirect("/")  # Then sending him to the main page.


    incorrect_login = False # Initially set to False, if set to True - then it will display additional text to the user.

    if request.method == "POST":

        email = request.form.get("email-field-register")

        password_user = request.form.get("password-field-register")

        query = email_query(email) # Saving the result of the email query into a variable.


        if query: # If a user with this exact email was found.

            try:

                hasher.verify(password=password_user, hash=query[4]) # The first argument - the unencrypted password that the user passed in the form.

                # Second - the hash stored in the database.

                resp = make_response(redirect("/"))

                two_m_exp = timedelta(days=60) + datetime.now()  # Setting the expiration date for the cookies for 2 months.

                resp.set_cookie(key="saved_cookies", value=str(query[0]), httponly=True, samesite="Lax", secure=True, partitioned=True, expires=two_m_exp)


                # secure: A boolean flag (True/False) indicating whether the cookie should only be transmitted over a secure HTTPS connection. => set to True - more security.

                # httponly: A boolean flag that, if set to true, makes the cookie inaccessible to client-side scripts (e.g., JavaScript), enhancing security against XSS attacks.

                # samesite: Controls when the cookie is sent with cross-site requests. Common values include Lax, Strict, and None.

                # Lax: Sends cookies with top-level navigations and safe HTTP methods (like GET).

                # partitioned: A flag, indicating that the cookie should be stored using partitioned storage, related to Cookies Having Independent Partitioned State (CHIPS).

                # For better protection against CSRF and XSS attacks + privacy benefits.


                return resp

            except argon2.exceptions.InvalidHashError:

                incorrect_login = True # First breaking point: if the .verify function raises a VerifyMismatchError, i.e., if a user with this email was found in the database, but the password and the hash of the password didn't match.

                return render_template("login.html", login_info=incorrect_login)

        else:

            incorrect_login = True # Second breaking point: this one if a user with such email was never even found in the database. (Query should be [], which is equal to None).

            return render_template("login.html", login_info=incorrect_login)




    return render_template("login.html", login_info=incorrect_login)


#---- Login With Google ----#


@app.route("/login/google")
def login_google(): # Initial login.


    if is_registered():

        return redirect("/")

    try:

        # Redirect to authorize_google_login function.

        redirect_uri = url_for('authorize_google_login', _external=True) # _external is used to control whether the generated URL is absolute or relative.

        # That is set to True here because of the Google pop-up window. (Since it's not a part of my Flask app).

        return google.authorize_redirect(redirect_uri)

    except Exception as e:

        app.logger.error(f"Error during login: {str(e)}")

        return "Error occurred during login", 500


# If the login was successful.
@app.route("/authorize/google/login")
def authorize_google_login(): # Where the user would consent the data to the server.

    # Fetching the data from the Google's server response.

    token = google.authorize_access_token() # Essential for gaining access to the user's Google data.

    user_info_endpoint = google.server_metadata["userinfo_endpoint"]

    res = google.get(user_info_endpoint)

    user_info = res.json()


    # Database shenanigans.


    query = email_query(user_info["email"])

    if query and query[4] == "google": # If the user's found, and they've registered with Google.

        resp = make_response(redirect("/"))

        two_m_exp = timedelta(days=60) + datetime.now()

        resp.set_cookie(key="saved_cookies", value=str(query[0]), httponly=True, samesite="Lax", secure=True, partitioned=True, expires=two_m_exp)

        return resp

    else: # If the user with this email wasn't found or his/her password isn't "google" - then it means that they didn't register with Google.

        return "Error occurred during login with Google. Perhaps you've used password to register previously or never even registered with this email before.", 500



#---- Sign-up Mechanism ----#


@app.route("/signup", methods=["GET", "POST"])
def sign_up_page():

    if is_registered():

        return redirect("/")


    error_msg = False # Initially set the email error to False.

    if request.method == "POST":

        fname = request.form.get("fname-field-register")

        lname = request.form.get("lname-field-register")

        email = request.form.get("email-field-register")

        password_user = request.form.get("password-field-register")


        query = email_query(email) # First DB query in order to spot the same email.


        if query: # I.e., if the result of the query is not None - then it means the same email was found in the DB.

            error_msg = True # Triggering the error in signup.html by setting it to True. (Check line 108).

            return render_template("signup.html", error=error_msg) # Triggering an error if the same email already exists in the database.

        # Hashing user's password.

        password_user = hasher.hash(password_user)

        # Inserting user into the database.

        with engine.connect() as connection:

            connection.execute(customer_table.insert(), {

                "FirstName": fname,

                "LastName": lname,

                "Email": email,

                "Password": password_user,

                "ProfilePicture": "https://img.icons8.com/?size=100&id=tZuAOUGm9AuS&format=png&color=000000", # Just a default image when the user registers for the first time. Will be replaced if the user decides to change the image.

                "InCart": 0,

                "Liked": 0,

            })

            connection.commit()


        query = email_query(email) # Second query in order to set the cookie.

        # This is inefficient ash... :(


        resp = make_response(redirect("/"))

        two_m_exp = timedelta(days=60) + datetime.now()

        resp.set_cookie(key="saved_cookies", value=str(query[0]), httponly=True, samesite="Lax", secure=True, partitioned=True, expires=two_m_exp)


        return resp

    return render_template("signup.html", error=error_msg)


#---- Register With Google ----#

# (Also supports login if the user's trying to register with a Google account that's already in the database).


@app.route("/register/google")
def register_google():

    if is_registered():

        return redirect("/")

    try:

        redirect_uri = url_for('authorize_google_register', _external=True)

        return google.authorize_redirect(redirect_uri)

    except Exception as e:

        app.logger.error(f"Error during login: {str(e)}")

        return "Error occurred during login", 500



# The route where the user will be redirected if the login was successful.
@app.route("/authorize/google/register")
def authorize_google_register(): # Where the user would consent the data to the server.

    token = google.authorize_access_token() # Essential for gaining access to the user's Google data.

    user_info_endpoint = google.server_metadata["userinfo_endpoint"]

    res = google.get(user_info_endpoint)

    user_info = res.json()

    # Database shenanigans.

    query = email_query(user_info["email"])


    resp = make_response(redirect("/")) # Setting up the response.

    two_m_exp = timedelta(days=60) + datetime.now()


    if query: # Checking if the user's already registered with their Google account.

        resp.set_cookie(key="saved_cookies", value=str(query[0]), httponly=True, samesite="Lax", secure=True, partitioned=True, expires=two_m_exp)

        return resp


    with engine.connect() as connection:

        connection.execute(customer_table.insert(), {

            "FirstName": user_info["given_name"],

            "LastName": user_info["family_name"],

            "Email": user_info["email"],

            "ProfilePicture": user_info["picture"],

            "Password": "google",

            "InCart": 0,

            "Liked": 0,

            # Just storing their passwords as "google".

            # The reason that it's not a security threat is because I hash all the passwords, even when the user's trying to log-in.

            # And this hash, by design, will never give just the word "google" as a hash result.

        })

        connection.commit()

    query = email_query(user_info["email"])

    resp.set_cookie(key="saved_cookies", value=str(query[0]), httponly=True, samesite="Lax", secure=True, partitioned=True, expires=two_m_exp)

    return resp


def product_page():

    pass


def checkout(): # Pls make a "Refund Policy" on this page. (Even if it'll be empty lul)

    pass

def search():

    pass


def upload_item():

    pass


def user_profile_edit(): # Will be responsible for showing user's profile. (And the possibility to modify it).

    pass

def item_status(): # Will be responsible for displaying the status of various products. (The status itself won't change, but it'll be pretty cool still).

    pass


@app.route("/logout")
def logout():

    resp = make_response(redirect("/"))

    if not is_registered():  # If user's trying to log out... without having an account to log out from.

        return redirect("/login")  # Then sending him to the login page if he/she is not registered.

    else:

        resp.delete_cookie("saved_cookies", secure=True, httponly=True, partitioned=True, samesite="Lax")

        return resp


if __name__ == "__main__":

    app.run(debug=True)
