# TODO: pls create multiple subdivisions of functions (e.g. PasswordManager, TableCreation, DB_Setup, etc.), the lag is just too much, and one 700+ lines python file is not good too :3
# Now about 1100+ lines lul.
# Now about 1700+ lines omegalul

# Another TODO: at the end of the production, please categorize JS scripts + css (if possible) into files.

# I'll prolly do it closer to the end of the production, for now I want to have everything in one file.

# TODO: as a sidequest - let the user delete their own reviews.

# TODO: (Closer to the end of the production) - adjust mobile frontend.

# TODO: (Closer to the end of the production) - Create fake test accounts using stripe.Account.create, then insert their IDs into the DB. (Check if it's possible to set payouts_enabled, charges_enabled and transfers to True in these accounts).

#---- Imports ----#


import os
import json
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, request, make_response, url_for, jsonify, session, Response
from sqlalchemy import Text, Numeric, Integer, BOOLEAN, ARRAY, create_engine, MetaData, Column, Table, LargeBinary, select, func  # For DB interactions.
from sqlalchemy.orm import sessionmaker
import argon2 # For hashing passwords.
from authlib.integrations.flask_client import OAuth # For authorization with Google.
from datetime import datetime, timedelta # For generating a 2-month expiry for a cookie.
import stripe # For payment processing. (Using offline API Key, because I can't get it working with online version :3)
import cloudinary # Cloud for storing images and videos.
import cloudinary.uploader as cloud_upload
from werkzeug.utils import secure_filename # For preventing directory attacks. (Removes stuff like "/", which can lead to the attackers going up through the directory).
from werkzeug.datastructures import FileStorage # Chiefly used in the exceeds_file_size_limit function.
import magic # For securing user-uploaded files. (Checking image's MIME type + the magic numbers).
from itsdangerous import URLSafeSerializer, BadSignature # In order to cryptographically sign cookies.
import pyotp # For Two-Factor Authentication.
import qrcode # For creating Google Authentication QR-codes.
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
# For QR-code-image generation:
from base64 import b64encode, b64decode # In order to display the image without saving it to the folder and restore the original 32-bit encryption key.
from io import BytesIO # To save the images to a BytesIO object (in-memory).
from PIL import Image
import secrets # For generating 2FA recovery codes.
import string # Also a part of recovery code generation.
# RIP email verification + forgot password features :( too expensive for my project...
# Because I want this project to feel like it was made by a professional company, I'll have to use services like Mailgun, Mailjet, etc. The problem is that I'll have to own a DNS domain, which... costs money :(
from decimal import Decimal, ROUND_HALF_UP # For working with the prices and quantities. (Used in calculate_price API).


# !!!!!! Important information !!!!!!

# !!!!!! Don't forget to type "pip install python-magic-bin" (If you're on Windows) In the console, otherwise the "magic" library won't work with the error:

# "ImportError: failed to find libmagic. Check your installation"

# For other OS, check this: https://github.com/ahupp/python-magic/blob/master/README.md


# Please register in ngrok.com and then run these two commands:


# pip3 install ngrok; - for installation.

# ngrok http 3000; - After running localhost (pressing the "run" button), in order for upload page and Stripe API's onboarding process to work properly.

# Then use the ngrok's live link to access the website (i.e., https://synovial-wilton-unspilt.ngrok-free.dev/).

# Otherwise upload page, and all of its functionality, simply won't work.


#---- Password Hasher initialization ----#


hasher = argon2.PasswordHasher(  # Hashing user's password.

    time_cost=3,  # Number of iterations.
    memory_cost=70000, # 70 Mb in KiB.
    parallelism=8,  # Number of parallel threads.
    hash_len=32,  # Hash's length in bytes.
    type=argon2.Type.ID, # Using Argon2id version. (Most efficient, since it combines benefits of both Argon2d and Argon2i)

)


#---- App + Database + Stripe + Cloudinary Initializations ----#


# Loading .env

load_dotenv()


#---- App Initialization ----#


app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")


#---- Serializer Config ----#


serializer = URLSafeSerializer(app.secret_key)


#---- Cloudinary (Cloud Storage) Config ----#


cloudinary.config(

    cloud_name=os.getenv("CLOUDINARY_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY_REGULAR"),
    api_secret=os.getenv("CLOUDINARY_API_KEY_SECRET"),
    secure=True,

)


#---- Stripe Config ----#


stripe_keys = {

    "secret_key": os.getenv("SECRET_KEY_STRIPE"),
    "publish_key": os.getenv("PUBLISHABLE_KEY_STRIPE"),

}


stripe.api_key = stripe_keys["secret_key"]


stripe_endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET") # Will be useful when verifying the event of the webhook payment processing. (Check the /webhook endpoint).


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


#---- Database (PostgreSQL) initialization ----#


user = os.getenv("DB_USERNAME")
password = os.getenv("DB_PASSWORD")
host = os.getenv("DB_HOST")
port = os.getenv("DB_PORT")
name = os.getenv("DB_NAME")

# Declaring the URL of the Database:

DATABASE_URL = f"postgresql://{user}:{password}@{host}:{port}/{name}"

# Engine Declaration:

engine = create_engine(DATABASE_URL)


meta_data_obj = MetaData() # Where all the tables and columns will be stored.


# PLS PLS PLS PLS PLS KEEP EVERY SINGLE COLUMN NAME WITHOUT SPACEBARS!!

customer_table = Table(

    "Customer Data",

    meta_data_obj,

    Column("ID", Integer, primary_key=True, autoincrement=True),
    Column("FirstName", Text, nullable=False, unique=False),
    Column("LastName", Text, nullable=False, unique=False),
    Column("Email", Text, nullable=False, unique=True, index=True),
    Column("Password", Text, nullable=False),
    Column("InCartAmount", Integer, nullable=True), # Will store all the items the user has in cart.
    Column("ProfilePicture", Text, nullable=True),
    Column("Stripe", BOOLEAN, nullable=False),
    Column("Stripe_ID", Text, nullable=True),
    Column("TwoFA", BOOLEAN, nullable=False), # A boolean in order to easily check if the user has a 2FA turned on.
    Column("Night_mode", BOOLEAN, nullable=False),
    # 2FA parameters:
    Column("Encrypted_secret", LargeBinary, nullable=True),
    Column("Nonce", LargeBinary, nullable=True),
    Column("Temp_key", LargeBinary, nullable=True),
    Column("Recovery_codes", ARRAY(Text), nullable=True), # When the user connects the 2FA.
    # Change Account Credentials Permission:
    Column("Can_access_credentials", BOOLEAN, nullable=False), # Will be responsible for keeping the user locked from changing their account details unauthorized. (Check change_details function).

)

product_table = Table(

    "Product Data",

    meta_data_obj,

Column("ID", Integer, primary_key=True, autoincrement=True),
    Column("Name", Text, nullable=False),
    Column("Rating", Integer, nullable=False),
    Column("Price", Numeric, nullable=False),
    Column("Tags", ARRAY(Text), nullable=False, index=True),
    Column("Description", Text, nullable=False),
    Column("Images", ARRAY(Text), nullable=False),
    Column("OwnerID", Integer, nullable=False, index=True),

)

reviews_table = Table( # This table is responsible for storing all the reviews from the users. (Each comment - new entry).

    "Reviews Data",

    meta_data_obj,

    Column("ID", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, nullable=False, index=True),
    Column("product_id", Integer, nullable=False, index=True),
    Column("user_comment", Text, nullable=False),
    Column("user_rating", Integer, nullable=False),

)

in_cart_table = Table(  # Will store the data about the items the user has in the cart.

    "In Cart Data",

    meta_data_obj,

    Column("ID", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, nullable=False, index=True),
    Column("product_id", Integer, nullable=False, index=True),
    Column("quantity", Integer, nullable=False),
    Column("single_item_price", Numeric, nullable=False),

)

orders_items_table = Table( # One row per one product bought.

    # Will be used for both the customer and the merchant (With the merchant being able to change the item_status column via the interface).

    "Orders Data",

    meta_data_obj,

    Column("ID", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, nullable=False, index=True),
    Column("merchant_id", Integer, nullable=False, index=True),
    Column("product_id", Integer, nullable=False, index=True),
    Column("quantity", Integer, nullable=False),
    Column("item_status", Text, nullable=False, unique=False),
    Column("shipping_address", Text, nullable=False),
    Column("customer_phone", Text, nullable=False),
    Column("customer_email", Text, nullable=False),
    Column("customer_full_name", Text, nullable=False),
    Column("total_order_price", Numeric, nullable=False),
    Column("single_item_price", Numeric, nullable=False),
    Column("master_order_id", Integer, index=True, nullable=False),

)

master_orders_table = Table( # Just the order in general, not every single item the user's bought. (That's for the orders_items_table)

    "Master Orders Table",

    meta_data_obj,

    Column("order_id", Integer, primary_key=True, autoincrement=True),
    Column("buyer_id", Integer, index=True, nullable=False),
    Column("shipping_info", Text, nullable=False),
    Column("total_price", Numeric, nullable=False),

)

liked_items_table = Table(

    "Liked Items Data",

    meta_data_obj,

    Column("ID", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, nullable=False, index=True),
    Column("product_id", Integer, nullable=False, index=True),

)

# TODO: let the user search for every item in a certain category in the product_page.

# TODO: for late-stage development - create a seed data for the database using bulk_insert()

# In order to let all the users have a data by default when forking my project.

# I think I'll have like 4 products per category, so that index page and search will function properly.

# Hence, it'll prolly has 3 columns. One-to-many relationship.


# Creating all the tables and initiating session.

meta_data_obj.create_all(engine)

Session_db = sessionmaker(bind=engine)

session_db = Session_db()

# session_db.bulk_insert_mappings() !!!!!!!!!!!!!!!!!


#---- Important Functions ----#

#---- Cookie Management. ----#


def is_registered(): # Checks if the user's registered.

    # Returns a cookie.

    # Firstly it fetches a cookie, then it checks its signature since the user can simply change it by either using browser extensions, or simply going to the "application" part and changing it themselves.

    # Since I'm using user's ID that's stored in a cookie to register the user - this means that there's a high risk of one user impersonating another simply by changing their cookies.

    # If a cookie hasn't been set or BadSignature error's raised (i.e., if a user has tampered with a cookie) - returns None.

    # Else - returns the ID of the user.

    saved_cookie = request.cookies.get("saved_cookies")

    if saved_cookie: # If the user's registered and has a cookie - then using serializer, otherwise - just send an empty cookie.

        try:

            saved_cookie = serializer.loads(saved_cookie)["user_id"]

        except BadSignature: # Raised if a signature does not match.

            saved_cookie = None # Reject a cookie if it's been tampered with.

    return saved_cookie


def email_query(email: str): # In order to query the user by their email.

    return session_db.query(customer_table).where(customer_table.c.Email == email).first()


def id_query(id_input: int): # Does the same as the function above, but with an ID.

    return session_db.query(customer_table).where(customer_table.c.ID == id_input).first()


#---- 2FA Management -----#


# Does exactly what it says - just generates recovery for 2FA after the user's done with the main generation process.

def generate_2fa_recovery_codes(num_of_codes=5, code_length=11):

    return_codes = []

    full_chars_list = string.ascii_letters + string.digits

    while len(return_codes) < num_of_codes:

        random_code = "".join(secrets.choice(full_chars_list) for _ in range(code_length))

        return_codes.append(random_code)

    return return_codes


def hash_and_commit_recovery_codes(all_codes: list, user_id: int): # The codes generated in the function above will be shown only to the user, the DB will contain hashed versions of these codes.

    hashed_list = []

    for code in all_codes:

        hashed_code = hasher.hash(code)

        hashed_list.append(hashed_code)


    with engine.connect() as connection:

        connection.execute(

            customer_table.update().where(customer_table.c.ID == user_id).values(Recovery_codes=hashed_list)

        )

        connection.commit()


#---- Additional Security Functions ----#


ALL_ALLOWED_EXTENSIONS = ["jpeg", "png", "jpg"]


def check_file_allowed(filename: str) -> bool: # This function is responsible for checking if a file sent by the user has correct extension. (JPEG, PNG and .mp4 in my case).

    return "." in filename and filename.split(".", 1)[1].lower() in ALL_ALLOWED_EXTENSIONS

    # Checks if dot is in the name of the file. If it is - then it splits the string from the right (.rsplit) and checks the rightmost side if its extension is allowed.

    # If one of these conditions is not True - then returns False.


def exceeds_file_size_limit(file_object: FileStorage, max_file_size: int):

    # Takes two inputs - the file to check (file_object), and the file size (max_file_size), acting as the cap (in bytes).

    # Returns False if the file doesn't exceed the size, returns True if it does.


    current_pointer_pos = file_object.tell() # Outputs the current position of the pointer.

    file_object.seek(0, os.SEEK_END) # Moving the pointer to the last part of the file.

    file_size_bytes = file_object.tell() # Where the image's file size lies.

    file_object.seek(current_pointer_pos) # Moving the pointer to the beginning.

    # Checking if the file's size exceeds the one allowed by the max_file_size function; returning an appropriate Boolean.

    if file_size_bytes > max_file_size: return True

    else: return False


FILE_CONTENT_WHITELIST = ["image/jpeg", "image/jpg", "image/png"]

def check_image_content(file_object: FileStorage):

    mime = magic.from_buffer(file_object.read(4096), mime=True) # Reading the first 4096 bytes (a bit of an overkill, but just in case...) to determine its MIME type in order to determine whether it's an actual image.

    file_object.seek(0) # Return the pointer for saving.

    return mime in FILE_CONTENT_WHITELIST


def image_decode(file_object: FileStorage): # Checks whether the file, submitted by the user, is actually an image and not a malicious file, dressing up as an image.

    try:

        img = Image.open(file_object)

        img.verify() # Checking the internal consistency of the submitted image.

        file_object.seek(0) # Resetting the pointer, since verification invalidates the image object.

        return True

    except Exception:

        return False


def image_re_encode(file_object: FileStorage):

    img = Image.open(file_object)

    img_format = img.format # Getting the format of the image before the conversion, since it'll return None after the img.convert("RGB").

    img = img.convert("RGB") # Since it removes any suspicious formats + potentially dangerous metadata.

    clean_buffer_img = BytesIO() # Creating a clean in-memory file.


    # Re-encoding the image with adherence to its file format.

    if img_format == "JPEG" or img_format == "JPG":

        img.save(clean_buffer_img, format="JPEG", quality=90, optimize=True)

    else:

        img.save(clean_buffer_img, format="PNG", quality=90, optimize=True)

    clean_buffer_img.seek(0)

    return clean_buffer_img


def restrict_access_to_details(user_data): # If Can_access_credentials is True - then the function immediately sets it to False (In order to keep user's restriction to the data change page, locking it behind reauthorization).

    # If it's set to False - then it simply does nothing.

    if user_data[15]:

        user_id = user_data[0]

        with engine.connect() as connection:

            connection.execute(

                customer_table.update().where(customer_table.c.ID == user_id).values(Can_access_credentials=False)

            )

            connection.commit()


def give_permission_to_details(user_data):

    user_id = user_data[0]

    with engine.connect() as connection:
        connection.execute(

            customer_table.update().where(customer_table.c.ID == user_id).values(Can_access_credentials=True)

        )

        connection.commit()

def check_recovery_codes(all_recovery_codes: list, user_code_hash) -> bool: # A function that checks user's inputted recovery code.

    # As soon as the program finds correct recovery code it returns True.

    # If such code is not found - it returns False in the end.

    for recovery_code in all_recovery_codes:

        try:

            hasher.verify(password=user_code_hash, hash=recovery_code)

            return True

        except argon2.exceptions.VerifyMismatchError:

            continue


    return False


#---- Website Functionality ----#


# TODO - query main products here, in order not to query them everytime the user loads the main page.

@app.route("/like/<int:product_id>") # This route is responsible for adding a specific item to the user's "liked" pool.
def add_to_liked(product_id):

    # TODO: pls modify this :3

    user_cookies = is_registered()

    user_data_liked = id_query(int(user_cookies))

    # If the user's not registered or this item is already in the "liked_items" - then redirect him to the main page.

    if not user_cookies or product_id in user_data_liked[5]: return redirect("/")

    # If none of this returns True - then adding an ID of the product to the liked items of the user.

    user_data_liked[5].append(product_id)

    return redirect("/")


@app.route("/")
def main_page(): # Speaks for itself.

    if "temp_user_id" in session: session.clear()

    has_cookies = is_registered() # Checks user's browser for cookies. The HTML pages will change depending on the content of the variable.

    if has_cookies:

        user_data = id_query(int(has_cookies)) # Fetching all the data about the user, utilizing his ID.

        restrict_access_to_details(user_data)

        has_2fa = user_data[9]

        night_mode_data = user_data[10]

    else:

        user_data = None # In case has_cookies is None - then pass in the user's data as None too.

        has_2fa = False

        night_mode_data = False

    return render_template(

                            "index.html",

                           registered=has_cookies,

                           user_data=user_data,

                           liked_products=["B","B","B","B"],

                           in_cart_products=["B","B","B","B","B","B"],

                            has_2fa=has_2fa,

                            night_mode=night_mode_data,

                           )


#---- Log-in Mechanism ----#


@app.route("/login", methods=["GET", "POST"])
def login_page():

    if is_registered():  # If the user's trying to log in while already having an account.

        return redirect("/")  # Then sending them to the main page.


    incorrect_login = False # Initially set to False, if set to True - then it will display additional text to the user.

    if request.method == "POST":

        email = request.form.get("email-field-register")

        password_user = request.form.get("password-field-register")

        query = email_query(email) # Saving the result of the email query into a variable.


        if query: # If a user with this exact email was found.

            try:

                hasher.verify(password=password_user, hash=query[4]) # The first argument - the unencrypted password that the user passed in the form.

                # Second - the hash stored in the database.

                if not query[9]: # In case the user has no 2FA installed.

                    resp = make_response(redirect("/"))

                    two_m_exp = timedelta(days=60) + datetime.now()  # Setting the expiration date for cookies at 2 months.

                    resp.set_cookie(key="saved_cookies", value=serializer.dumps({"user_id": str(query[0])}), httponly=True, samesite="Lax", secure=True, partitioned=True, expires=two_m_exp)


                    # secure: A boolean flag (True/False) indicating whether the cookie should only be transmitted over a secure HTTPS connection. => set to True - more security.

                    # httponly: A boolean flag that, if set to true, makes the cookie inaccessible to client-side scripts (e.g., JavaScript), enhancing security against XSS attacks.

                    # samesite: Controls when the cookie is sent with cross-site requests. Common values include Lax, Strict, and None.

                    # Lax: Sends cookies with top-level navigations and safe HTTP methods (like GET).

                    # partitioned: A flag, indicating that the cookie should be stored using partitioned storage, related to Cookies Having Independent Partitioned State (CHIPS).

                    # For better protection against CSRF and XSS attacks + privacy benefits.

                    return resp

                else: # If the user has 2FA installed.

                    session["temp_user_id"] = query[0]

                    return redirect("/login-2fa")

            except argon2.exceptions.VerifyMismatchError:

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

        if not query[9]: # If the user doesn't have 2FA installed.

            resp = make_response(redirect("/"))

            two_m_exp = timedelta(days=60) + datetime.now()

            resp.set_cookie(key="saved_cookies", value=serializer.dumps({"user_id": str(query[0])}), httponly=True, samesite="Lax", secure=True, partitioned=True, expires=two_m_exp)

            return resp

        else:  # If the user has 2FA installed.

            session["temp_user_id"] = query[0]

            return redirect("/login-2fa")


    else: # If the user with this email wasn't found or his/her password isn't "google" - then it means that they didn't register with Google.

        return "Error occurred during login with Google. Perhaps you've previously used password to register, or maybe never even registered with this email before.", 500



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


        if query: # I.e., if the result of the query is not None - then it means that the same email was found in the DB.

            error_msg = True # Triggering the error in signup.html by setting it to True. (Check line 110).

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

                "InCartAmount": 0,

                "Stripe": False,

                "TwoFA": False,

                "Night_mode": False,

                "Can_access_credentials": False,

            })

            connection.commit()


        user_data = email_query(email) # Second query in order to set the cookie and get the user's data.

        # This is inefficient ash... :(


        resp = make_response(redirect("/")) # Will immediately redirect to the email verification page.

        two_m_exp = timedelta(days=60) + datetime.now()

        resp.set_cookie(key="saved_cookies", value=serializer.dumps({"user_id": str(user_data[0])}), httponly=True, samesite="Lax", secure=True, partitioned=True, expires=two_m_exp)

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

    if query: # If the user was found.

         if query[4] == "google": # If the user's found, and they've registered with Google.

            if not query[9]: # If the user doesn't have 2FA installed.

                resp.set_cookie(key="saved_cookies", value=serializer.dumps({"user_id": str(query[0])}), httponly=True, samesite="Lax", secure=True, partitioned=True, expires=two_m_exp)

                return resp

            else:  # If the user has 2FA installed.

                session["temp_user_id"] = query[0]

                return redirect("/login-2fa")

         else: # If user's "password" value is not equal to "google" - then it means that: 1 - they've registered with this email sometime in the past, and 2 - they've registered manually, without using Google.

             return "Error occurred during a sign up using Google. Maybe you've already registered with this email manually?"


    else: # If the user hasn't been found in the DB at all.

        with engine.connect() as connection:

            connection.execute(customer_table.insert(), {

                "FirstName": user_info["given_name"],

                "LastName": user_info["family_name"],

                "Email": user_info["email"],

                "ProfilePicture": user_info["picture"],

                "Password": "google",

                # Just storing their passwords as "google".

                # The reason that it's not a security threat is because I hash all the passwords, even when the user's trying to log in.

                # And this hash, by design, will never give just the word "google" as a hash result.

                "InCartAmount": 0,

                "Stripe": False,

                "TwoFA": False,

                "Night_mode": False,

                "Can_access_credentials": False,

            })

            connection.commit()

        user_data = email_query(user_info["email"])

        resp.set_cookie(key="saved_cookies", value=serializer.dumps({"user_id": str(user_data[0])}), httponly=True, samesite="Lax", secure=True, partitioned=True, expires=two_m_exp)

        return resp

@app.route("/login-2fa", methods=["GET", "POST"])
def two_fa_required(): # Responsible for checking user's 2FA code when they try to log in.

    if "temp_user_id" not in session: return redirect("/")

    user_data = id_query(session["temp_user_id"])

    user_encrypted_secret, user_encrypted_nonce, user_id = user_data[11], user_data[12], user_data[0]

    encr_tool = ChaCha20Poly1305(b64decode(os.getenv("SECRET_ENCRYPTION_KEY")))

    if request.method == "POST":

        # Getting user's inputted full code.

        full_code = f"{request.form.get('num1')}{request.form.get('num2')}{request.form.get('num3')}{request.form.get('num4')}{request.form.get('num5')}{request.form.get('num6')}"

        # Not the cleanest code... :(

        # Verifying user's code.

        decrypted_key = encr_tool.decrypt(user_encrypted_nonce, user_encrypted_secret, associated_data=user_id.to_bytes())

        # Generating a URL using the key.

        decrypted_utf = decrypted_key.decode("utf-8")


        verify_totp = pyotp.TOTP(decrypted_utf).verify(full_code)

        if verify_totp:

            session.clear() # Resetting the session.

            resp = make_response(redirect("/"))

            two_m_exp = timedelta(days=60) + datetime.now()  # Setting the expiration date for cookies at 2 months.

            resp.set_cookie(key="saved_cookies", value=serializer.dumps({"user_id": str(user_id)}), httponly=True,
                            samesite="Lax", secure=True, partitioned=True, expires=two_m_exp)

            return resp

        else:

            return render_template("login_2fa.html", error_code=True)


    return render_template("login_2fa.html", error_code=False)

@app.route("/cart")
def cart_display():

    has_cookies = is_registered()

    if "temp_user_id" in session: session.clear()


    if not has_cookies: return redirect("/login")


    user_data = id_query(int(has_cookies))

    restrict_access_to_details(user_data)

    has_2fa = user_data[9]

    night_mode_data = user_data[10]


    stmt = select( # Querying relative information about the products that the user has in their cart, using product_id and user_id from the in_cart_table.

        product_table.c.Name,
        product_table.c.Price,
        product_table.c.Images[1], # Fetching the first image. (I don't know why its index is 1 and not 0).
        product_table.c.ID,
        in_cart_table.c.quantity,

    ).outerjoin(in_cart_table, product_table.c.ID == in_cart_table.c.product_id).where(

        in_cart_table.c.user_id == has_cookies

    )


    with engine.connect() as connection:

        all_in_cart = connection.execute(stmt).fetchall()


    # Calculating the total price:

    total_price = 0

    if all_in_cart: # In case the user actually has something in their cart.

        for single_product in all_in_cart:

            total_price += single_product[1] * single_product[4] # Calculating the prices of the product (index 1), multiplied by the quantity of the product.


    return render_template("cart.html", has_2fa=has_2fa, night_mode=night_mode_data, registered=has_cookies, user_data=user_data, user_products=all_in_cart, total=total_price)


@app.route("/add-to-cart/<int:product_id>")
def add_to_cart(product_id):

    has_cookies = is_registered()

    if not has_cookies: return redirect("/login")


    full_product_info = session_db.query(product_table).where(product_table.c.ID == product_id).first()


    owner_id = full_product_info[7]

    product_price_info = full_product_info[3] # For updating the total in user's cart.


    previous_user_amount = session_db.query(customer_table).where(customer_table.c.ID == has_cookies).first()[5] # Will help determine how many items the user has in their cart, if it's above 15 - then it'll show an error.

    if previous_user_amount + 1 >= 21: pass

    elif owner_id == has_cookies: pass

    # These two checks above are just in case stuff, since the user can still modify the HTML and send POST request to this API.

    else:

        with engine.connect() as connection:

            connection.execute( # Updating the In Cart Table.

                in_cart_table.insert(), {

                        "user_id": has_cookies,

                        "product_id": product_id,

                        "quantity": 1,

                        "single_item_price": product_price_info,

                },

            )

            connection.execute(

                customer_table.update().where(customer_table.c.ID == has_cookies).values(

                    InCartAmount=previous_user_amount + 1 # Updating the amount of items that the user has.

                )

            )

            connection.commit()

    return redirect(url_for("product_page", product_id=product_id))

@app.route("/api/calculate-price", methods=["POST"]) # This API is responsible for calculating the total price of all the items the user has in their cart. (Adhering to the quantity as well).
def calculate_price():

    user_cookies = is_registered()

    if not user_cookies: return redirect("/login")

    # Getting the request.

    data = request.get_json()

    # Fetching the data from the request.

    id_of_the_item = data["id"]

    type_of_action = data["action"]


    prev_total_price = session_db.query(func.sum(in_cart_table.c.single_item_price * in_cart_table.c.quantity)).where(in_cart_table.c.user_id == user_cookies).first()[0] or 0.0 # Query the previous price from the DB. (Since the frontend one is too risky and insecure).

    quantity_of_the_item = session_db.query(in_cart_table).where(in_cart_table.c.product_id == id_of_the_item).where(in_cart_table.c.user_id == user_cookies).first()[3] # Querying the quantity of an individual item.


    if quantity_of_the_item == 3 and type_of_action == "plus" or quantity_of_the_item == 1 and type_of_action == "minus": return jsonify({"total": prev_total_price})

    # This line above is necessary, since the user can switch between the pages of the products and then come back to the cart page, where the values on the frontend will be outdated, but the values in the database will be up-to-date. (e.g. 2 on the frontend - the user can still add one more item to the cart, but in the database - it'll be 3, thus, making the amount of items to be equal to 4).


    prev_price = session_db.query(product_table).where(product_table.c.ID == id_of_the_item).first()[3] # Querying the price of an individual item (in order to not fetch it from the frontend).

    if type_of_action == "plus": # If the user's trying to add one to the quantity of an item.

        with engine.connect() as connection:

            connection.execute(

                in_cart_table.update().where(in_cart_table.c.user_id == user_cookies, in_cart_table.c.product_id == id_of_the_item).values(quantity=in_cart_table.c.quantity + 1)

            )

            # Increasing the quantity of the item by 1 in the DB.

            connection.commit()

        # Calculating the final price.

        new_total_price = Decimal(str(prev_total_price)) + prev_price

        new_total_price = new_total_price.quantize(new_total_price, rounding=ROUND_HALF_UP) # In order to add a float to a Decimal (this data type came from the database), and then having the final price with only 2 digits left after the decimal point,

        return jsonify({"total": round(new_total_price, 2)})


    elif type_of_action == "minus": # If the user's trying to reduce the quantity by one.

        with engine.connect() as connection:

            connection.execute(

                in_cart_table.update().where(in_cart_table.c.user_id == user_cookies, in_cart_table.c.product_id == id_of_the_item).values(quantity=in_cart_table.c.quantity - 1)

            )

            # Decreasing the quantity of the item by 1 in the DB.

            connection.commit()

        new_total_price = Decimal(str(prev_total_price)) - prev_price

        new_total_price = new_total_price.quantize(new_total_price, rounding=ROUND_HALF_UP)

        return jsonify({"total": round(new_total_price, 2)})


    elif type_of_action == "del": # If the user's trying to delete the item.

        with engine.connect() as connection:

            connection.execute(

                in_cart_table.delete().where(in_cart_table.c.user_id == user_cookies, in_cart_table.c.product_id == id_of_the_item),

            )

            connection.execute(

                customer_table.update().where(customer_table.c.ID == user_cookies).values(InCartAmount=customer_table.c.InCartAmount - 1)  # Decreasing the amount of items the user has.

            )

            connection.commit()

        new_total_price = Decimal(str(prev_total_price)) - (prev_price * quantity_of_the_item)

        new_total_price = new_total_price.quantize(new_total_price, rounding=ROUND_HALF_UP)

        return jsonify({"total": round(new_total_price, 2)})


    return None # There really is no reason for this return statement to exist. But my OCD will be mad at so many dim-yellow squiggly lines here because of the "no explicit return statement" warning >:3


@app.route("/create-checkout-session", methods=["POST"])
def create_stripe_checkout_session(): # When the user's proceeded to the checkout after modifying their cart.

    has_cookies = is_registered()

    if not has_cookies: return redirect("/login")


    stmt = (select( # Querying relative information about the products that the user has in their cart, using product_id and user_id from the in_cart_table.

        # Long story short, same query as it was before in the cart, but with a fancy hat. (I.e., calculating the total price using quantities and prices from the DB).

        product_table.c.Name,
        product_table.c.Description,
        product_table.c.Price,
        product_table.c.Images[1],
        customer_table.c.Stripe_ID,
        in_cart_table.c.quantity,
        in_cart_table.c.product_id,
        in_cart_table.c.user_id,
        product_table.c.OwnerID,


    ).join(in_cart_table, product_table.c.ID == in_cart_table.c.product_id)

    .join(customer_table, product_table.c.OwnerID == customer_table.c.ID)

    .where(

        in_cart_table.c.user_id == has_cookies

    ))

    with engine.connect() as connection:

        all_in_cart = connection.execute(stmt).fetchall()


    # Fetching all the relative data for the Stripe session.

    line_items = []

    metadata_checkout = { # This dictionary will be built up during the all_in_cart loop, but will be passed as an argument during the checkout session. (This is done in order to split the payment between multiple merchants).

        "seller_amount": [],
        "seller_stripe_id": [],
        "buyer_id": has_cookies,
        "product_id": [],
        "product_quantity": [],
        "seller_db_id": [],
        "single_item_price": [],

    }

    for single_item in all_in_cart:

        line_items.append({

            "price_data": {

                "currency": "usd",

                "unit_amount_decimal": str(int(single_item[2] * 100)), # Since this argument accepts only in cents.billing_scheme

                "product_data": {

                    "name": single_item[0],

                    "description": single_item[1],

                    "images": [single_item[3]],

                },

            },

            "quantity": single_item[5]

        })

        # Appending the data to metadata.

        metadata_checkout["seller_amount"].append(str(int((single_item[2] * 100) * single_item[5])))

        metadata_checkout["seller_stripe_id"].append(str(single_item[4])) # Storing the merchant's IDs in the metadata. (So that i can redistribute the money across the merchants).

        # Appending information about the product. (Necessary for the DB).

        metadata_checkout["product_id"].append(single_item[6])

        metadata_checkout["product_quantity"].append(single_item[5])

        metadata_checkout["seller_db_id"].append(single_item[8])

        metadata_checkout["single_item_price"].append(str(single_item[2]))


    # Converting this metadata into JSON (Since stripe.checkout.Session.create metadata accepts only strings as both keys and values).

    metadata_as_string = json.dumps(metadata_checkout) # !!!!!!!!!!!!!

    # The json.dumps() function converts a Python object (such as a dictionary or list) into a JSON-formatted string.


    # Creating a Stripe Checkout session using the data fetched above.

    session_stripe = stripe.checkout.Session.create(

        mode = "payment",

        success_url = "https://synovial-wilton-unspilt.ngrok-free.dev/order/stripe/success?session_id={CHECKOUT_SESSION_ID}",

        cancel_url = "https://synovial-wilton-unspilt.ngrok-free.dev/cart",

        line_items = line_items,

        phone_number_collection = { "enabled": True },

        shipping_address_collection = {

            "allowed_countries": ["US", "CA", "GB", "AU", "DE", "FR", "JP", "SG", "CN", "IN", "IT", "ES"]

        },

        billing_address_collection = "required",

        metadata = {

            "main_key": metadata_as_string,

        }

    )


    return {"url": session_stripe.url}

@app.route("/webhook-money-distribution", methods=["POST"])
def money_distribution(): # Does exactly what it says - checks if the payment was successful - if it was - then it collects all the Stripe IDs of the merchants, and then redistributes user's money to all the merchants.

    payload = request.data

    event = None


    try:

        dumped_payload = json.loads(payload)


        event = stripe.Event.construct_from(

            dumped_payload, stripe.api_key

        )


    except ValueError as e: # Invalid payload. (Like if the parameters of the request are incorrect or the request itself was parsed too early).

        return f"Error with the payload: {e}", 400


    # Verifying the endpoint secret.

    sig_header = request.headers.get("stripe-signature")

    try:

        event = stripe.Webhook.construct_event(

            payload, sig_header, stripe_endpoint_secret

        )

    except stripe.error.SignatureVerificationError as e:

        print(f"Something bad happened with the signature :(  {str(e)}")

        return jsonify(success=False)


    # Handling the event + DB actions.


    if event.type == "checkout.session.completed":

        session_payment = event["data"]["object"]


        if session_payment["payment_status"] == "paid":


            # Getting the charge ID for the source_transaction.

            payment_intent_session = session_payment["payment_intent"]


            payment_intent_retrieve = stripe.PaymentIntent.retrieve(

                payment_intent_session,

            )

            source_transaction = payment_intent_retrieve["latest_charge"] # The ID of the charge. (Used in order to specify the source_transaction when calling the stripe.Transfer.create, as not specifying this will cause an insufficient funds error, since Stripe will try to get the money for this transfer from my bank account).


            metadata_checkout_session = json.loads(session_payment["metadata"]["main_key"])

            customer_email = session_payment["customer_details"]["email"]

            customer_phone = session_payment["customer_details"]["phone"]

            customer_provided_address = session_payment["customer_details"]["address"]

            customer_provided_full_name = session_payment["collected_information"]["shipping_details"]["name"]

            total_order_price = session_payment["amount_total"]

            customer_full_shipping_address = f"{customer_provided_address.get("country")} {customer_provided_address["state"] if customer_provided_address["state"] else ""} {customer_provided_address.get("city")} {customer_provided_address.get("line1")} {customer_provided_address["line2"] if customer_provided_address.get("line2") else ""} {customer_provided_address.get("postal_code")}".replace("  ", " ")

            # In the gigantic line of code above I fetch the entire user-provided address, and then glue it into one string. And then reduce any double spaces.


            # Creating a hashmap with all the sellers and the amount of money that has to go to them.

            seller_hash = {}

            # Fetching data form metadata. (Organizing it conveniently).

            full_metadata_seller_amount = metadata_checkout_session["seller_amount"]

            full_metadata_seller_ids = metadata_checkout_session["seller_stripe_id"]


            # Looping through all the seller's IDs and the amount of money that needs to be distributed to them.

            for i in range(len(full_metadata_seller_amount)): # Using a single index i to loop through both lists.

                if full_metadata_seller_ids[i] not in seller_hash:

                    seller_hash[full_metadata_seller_ids[i]] = int(full_metadata_seller_amount[i])

                else: seller_hash[full_metadata_seller_ids[i]] += int(full_metadata_seller_amount[i])


            # In the end I'll have a hashmap with all the sellers IDs and the total amount of money that will be sent to them, using user's money as the source of the transaction.


            for merchant_id, amount_merchant in seller_hash.items():

                transfer_key = f"transfer_{session_payment["id"]}_{merchant_id}" # Acting as an idempotency key. (Basically a key that ensures the transfer will not happen twice because of, for instance, a random network error).

                transfer = stripe.Transfer.create(

                        amount = amount_merchant,

                        currency = "usd",

                        source_transaction = source_transaction,

                        destination = merchant_id,

                        idempotency_key = transfer_key,

                )


            # Updating the DB.

            with engine.connect() as connection:

                # Creating the master order. (An "umbrella-order", which will contain all the products the user's ordered).

                result = connection.execute(

                    master_orders_table.insert().returning(master_orders_table.c.order_id), { # .returning() since I need to get the master_order's id to pass to all the products below.

                        "buyer_id": metadata_checkout_session["buyer_id"],

                        "shipping_info": customer_full_shipping_address,

                        "total_price": total_order_price/100, # Converting the price from cents to dollars.

                    }

                )

                new_master_order_id = result.fetchone().order_id # Getting the ID inserted part.


                # Creating the "rows" list in order to bulk-insert it into a DB.

                rows = [

                {

                    "user_id": metadata_checkout_session["buyer_id"],

                    "merchant_id": seller_id,

                    "product_id": product_id,

                    "quantity": quantity,

                    "item_status": "Order Placed",

                    "shipping_address": customer_full_shipping_address,

                    "customer_email": customer_email,

                    "customer_phone": customer_phone,

                    "customer_full_name": customer_provided_full_name,

                    "total_order_price": total_order_price/100, # Same as "total_price" in the master order.

                    "single_item_price": single_item_price,

                    "master_order_id": new_master_order_id,

                }

                for seller_id, product_id, quantity, single_item_price in zip( # Using zip() function in order to avoid using "for j in range" loops.

                    metadata_checkout_session["seller_db_id"],

                    metadata_checkout_session["product_id"],

                    metadata_checkout_session["product_quantity"],

                    metadata_checkout_session["single_item_price"],

                )

            ]



                connection.execute( # Bulk-inserting all the data from the "rows" variable.

                    orders_items_table.insert(), rows

            )

                connection.execute( # Deleting all the items from the in_cart_table.

                    in_cart_table.delete().where(in_cart_table.c.user_id == metadata_checkout_session["buyer_id"])

            )

                connection.execute( # Setting the InCartAmount of the user to 0.

                    customer_table.update().where(customer_table.c.ID == metadata_checkout_session["buyer_id"]).values(InCartAmount=0)

            )

                connection.commit()

    return Response(status=200)


@app.route("/order/stripe/success")
def successful_payment_page(): # Redirects the user after the payment is complete. (Mostly for the frontend purposes, webhook is the one responsible for all the transfers and database changes).

    session_payment = request.args.get("session_id")

    if not session_payment: return redirect("/")

    user_cookies = is_registered() # In order to get the data on user's night mode.

    night_mode_data = session_db.query(customer_table).where(customer_table.c.ID == user_cookies).first()[10]

    # Retrieving all the necessary information to display to the user.

    session_payed = stripe.checkout.Session.retrieve(session_payment)

    address_dict = session_payed["collected_information"]["shipping_details"]["address"]


    return render_template("success_stripe.html", address_details=address_dict, full_name=session_payed["customer_details"]["name"], phone_number=session_payed["customer_details"]["phone"], customer_email=session_payed["customer_details"]["email"], total=session_payed["amount_total"]/100, night_mode=night_mode_data)


@app.route("/product-page/<int:product_id>")
def product_page(product_id):

    user_cookies = is_registered()

    if not user_cookies:

        night_mode = False

        user_data = None

        has_2fa = None

        in_cart_amount_user = 0

    else:

        user_data = id_query(int(user_cookies))

        night_mode = user_data[10]

        has_2fa = user_data[9]

        in_cart_amount_user = user_data[5]

    error_message = None # Will be equal to the error message if the restriction is hit by the user. (Stuff like the owner of the item trying to add their own product to the cart, or the user trying to add a product they already have in their cart, etc.)

    # For now, the error message will be None, since the user didn't do anything wrong.

    # Querying the data about the product using an ID from the URL.

    product_data = session_db.query(product_table).where(product_table.c.ID == product_id).first()

    # Querying the data about the user who uploaded the product.

    user_data_upload = session_db.query(customer_table).where(product_data[7] == customer_table.c.ID).first()


    if int(user_cookies) == product_data[7]: error_message = "Owner can't add to the cart or write a review on their own product"

    elif in_cart_amount_user + 1 >= 21: error_message = "Amount of items in the cart can't exceed 20"


    return render_template("product_page.html", night_mode=night_mode, registered=user_cookies, user_data=user_data, has_2fa=has_2fa, product_data=product_data, uploaded_fname=user_data_upload[1], uploaded_lname=user_data_upload[2], uploaded_pfp=user_data_upload[6], error_message=error_message)


@app.route("/reviews/<int:product_id>", methods=["GET", "POST"])
def reviews(product_id):

    user_cookies = is_registered()

    has_review = False # The main function of this variable is to detect whether the user's written a review before. Depending on that, the frontend will change.

    user_uploaded_comment, user_uploaded_rating = None, None # Will be filled with text if the user's left a comment before, otherwise will stay None.

    is_owner = False # A "flag" that will determine whether the user that's trying to access this page is an owner of the product.

    # If they're - then set this variable to True. Because of this, the user won't be able to leave reviews on their own product.


    if not user_cookies:

        night_mode = False

        user_data = None

        has_2fa = None

    else:

        user_data = id_query(int(user_cookies))

        night_mode = user_data[10]

        has_2fa = user_data[9]

        is_owner = True if session_db.query(product_table).where(product_table.c.ID == product_id).where(product_table.c.OwnerID == user_cookies).first() else False

        # If the DB query above returned something, then set is_owner to True, since owners shouldn't leave reviews on their own product.

        # If the user that's trying to access this page isn't an owner - then no changes made to the is_owner variable.


    possible_user_review = session_db.query(reviews_table).where(reviews_table.c.product_id == product_id).where(reviews_table.c.user_id == user_cookies).first() # Trying to fetch the data about whether the user already has a review on this specific product.


    if possible_user_review: # I.e., if the user's left a comment previously.

        has_review = True

        user_uploaded_comment = possible_user_review[3]

        user_uploaded_rating = possible_user_review[4]



    stmt = select( # This form of loading applies a JOIN to the given SELECT statement so that related rows are loaded in the same result set.

        # In order to query all the up-to-date data about the users who left reviews on a specific product. (Using OUTER JOIN in order to avoid N + 1 inefficiency/loading huge chunks of data at once).

        reviews_table.c.user_comment,
        reviews_table.c.user_rating,
        customer_table.c.FirstName,
        customer_table.c.LastName,
        customer_table.c.ProfilePicture,

    ).outerjoin(reviews_table, customer_table.c.ID == reviews_table.c.user_id).where(

        reviews_table.c.product_id == product_id

    )

    with engine.connect() as connection:

        users_query_result = connection.execute(stmt).fetchall()



    if request.method == "POST":

        if not user_cookies: return redirect("/login")


        new_user_rating = request.form["rating"]

        new_user_comment = request.form["user-comment-review"]


        if has_review: # If the user's editing an already existing review.

            with engine.connect() as connection:

                connection.execute(

                    reviews_table.update().where(reviews_table.c.product_id == product_id).where(reviews_table.c.user_id == user_cookies).values(user_comment=new_user_comment, user_rating=new_user_rating)

                )

                connection.commit()

        else: # If the user's writing a new comment.

            with engine.connect() as connection:

                connection.execute(

                    reviews_table.insert(), {

                        "user_id": user_cookies,

                        "product_id": product_id,

                        "user_comment": new_user_comment,

                        "user_rating": new_user_rating,

                    }

                )

                connection.commit()


        # Calculating a new rating for the product:

        prev_stars = session_db.query(reviews_table).where(reviews_table.c.product_id == product_id).all()

        all_reviews = len(prev_stars)  # Getting the total amount of reviews prior to the user's review.

        total_star = 0

        if prev_stars:

            for single_star in prev_stars:
                total_star += single_star[4]  # Getting the total amount of stars prior to the user's review.


        new_full_rating = total_star // all_reviews

        with engine.connect() as connection:

            connection.execute(

                product_table.update().where(product_table.c.ID == product_id).values(Rating=new_full_rating)

            )

            connection.commit()


        return redirect(url_for("reviews", product_id=product_id))


    return render_template("reviews.html", night_mode=night_mode, registered=user_cookies, user_data=user_data, has_2fa=has_2fa, product_data_reviews=users_query_result, product_id=product_id, has_review=has_review, user_comment=user_uploaded_comment, user_rating=user_uploaded_rating, is_owner=is_owner)


def search():

    pass


@app.route("/upload", methods=["GET", "POST"])
def upload_item():

    if "temp_user_id" in session: session.clear()

    user_cookies = is_registered()


    if not user_cookies: return redirect("/login")


    user_data = id_query(int(user_cookies))  # If the user's registered - then getting all the data from his cookies.

    restrict_access_to_details(user_data)


    if not user_data[8]: return render_template("striperequired.html", night_mode = user_data[10], registered=user_cookies, user_data=user_data, has_2fa = user_data[9]) # If the user doesn't have an ID associated with their account.

    if not user_data[7]: # If the user does have an ID associated with the account, but doesn't have a Stripe column equal to True - then doing the steps below:

        try: # If the user came back to the page after completing an onboarding process.

            new_account_stripe = stripe.Account.retrieve(user_data[8]) # Getting user's Stripe account using his ID. (Putting it in the try - except statement just in case).

            if new_account_stripe["capabilities"]["transfers"] == "active" and new_account_stripe["charges_enabled"] and new_account_stripe["payouts_enabled"] and not new_account_stripe["requirements"]["currently_due"]: # These keys have all the necessary information about what the user should complete before uploading items.

                # If these keys are either set to True or "active", or None - then it means that the user just completed the onboarding process - and the Stripe key column's yet to be changed.

                with engine.connect() as connection:

                    connection.execute(

                        customer_table.update().where(customer_table.c.ID == user_cookies).values(Stripe=True) # In that case - setting the Stripe column to True.

                    )

                    connection.commit()

            else: return render_template("striperequired.html", night_mode=user_data[10], registered=user_cookies, user_data=user_data, has_2fa = user_data[9])

            # But if at least one of them doesn't meet the requirements - then it means that the user returned to the page while completing onboard or didn't fully complete the onboarding process. (Like having some problems with the ID or SSN, etc.)

            # In this case - return them to the previous page as they didn't fully complete the onboarding, which is necessary for the product upload feature.


        except stripe.StripeError as e: # Juuuuuuuuust in case...

            app.logger.error(str(e))

            return "There was a problem with Stripe login. We're sorry for the inconvenience.", 500


    if request.method == "POST": # If the user's completed the form and uploaded all the necessary data.


        product_title = request.form.get("product_name")

        product_descr = request.form.get("product_description")


        if not product_descr: product_descr = "No description provided." # If user left the description field empty - then it's an empty string - in that case submitting "No description provided", which will be passed onto the database.


        product_price = request.form.get("product_price")

        all_product_tags = request.form.getlist("all-tags-upload")

        all_imgs = request.files.getlist("product_img")[:5] # Cutting the amount of images up to 5. (In case the user's changed the frontend JS and is trying to submit more than that).

        db_upload_images = []

        for single_img in all_imgs:

            # Modifying user's image name by removing any malicious characters within the filename.

            single_img.filename = secure_filename(single_img.filename)

            # Then, using this secured filename, checking if the file has correct extension and if the file size is correct, since the frontend JS is convenient, but not secure enough.

            if check_file_allowed(single_img.filename) and not exceeds_file_size_limit(single_img, 1500000) and check_image_content(single_img) and image_decode(single_img):

                # Re-encoding the image after decoding it. (This function returns a buffer).

                single_img = image_re_encode(single_img)

                # If it does - uploading the buffer to Cloudinary.

                upload_result = cloud_upload.upload(single_img)

                # Adding image link to the list that will be uploaded to the database later on.

                db_upload_images.append(upload_result["secure_url"])


            else: pass # If it doesn't have the right file type or exceeds the file size limit - simply not appending it to the final list.


        if not db_upload_images: return redirect("/upload") # If the db_upload_images is empty - then it means that the user's modified the frontend JS, jettisoning the file size controls.

        # In that case - don't commit this to the DB and redirect the user to the upload page.

        with engine.connect() as connection:

            connection.execute(product_table.insert(), {

                "Name": product_title,

                "Rating": 0,

                "Price": float(product_price),

                "Tags": all_product_tags,

                "Reviews": [],

                "Description": product_descr,

                "Images": db_upload_images,

                "OwnerID": user_cookies,

            })

            connection.commit()


        return jsonify({"redirect": "/"}) # Since I'm modifying formData in the upload.html, I need to upload a JSON.


    return render_template("upload.html", night_mode=user_data[10])


@app.route("/stripe_registry")
def stripe_registration(): # Where the user will be redirected to if they clicked "Register in Stripe". The main purpose of this URL - to create user account on stripe (using their ID, passed in the URL) - and then redirect them to onboarding page.

    cookie_data = is_registered()

    user_full_data = id_query(int(cookie_data))


    if not user_full_data: return "User registration error.", 500 # Throwing an error if the query didn't find any email, related to the user's ID.

    if user_full_data[8]: return redirect("/onboard") # Immediately redirect the user to the onboarding process if they already have a Stripe ID assigned to their profile.

    # This likely means that they didn't fully complete the onboarding process (i.e., left a few fields unconfirmed), then immediately redirect them to the onboarding session, since they don't need another Stripe ID.

    try:

        # Creating a Stripe Account:

        new_account = stripe.Account.create(

            email=user_full_data[3],
            controller={
                    "fees": {"payer": "application"},
                    "losses": {"payments": "application"},
                    "stripe_dashboard": {"type": "express"},
            },

            capabilities={
                    'card_payments': {'requested': True}, # Enabling card payment capability.
                    'transfers': {'requested': True}, # As well as transfers (as in, transfer between the users) capability.
            },

        )


        account_id = new_account.id

        with engine.connect() as connection:

            connection.execute(

                customer_table.update().where(customer_table.c.ID == cookie_data).values(Stripe_ID=account_id) # Updating the value of their stripeID.

            )

            connection.commit()

        return redirect("/onboard")  # Redirecting the user to the onboarding URL if everything was successful.


    except stripe.StripeError as e:

        app.logger.error(f"Stripe Registry Failed: {str(e)}")

        return "Error with Stripe account creation", 500


@app.route("/onboard")
def onboard_page(): # Where the user will be redirected if they: 1 - agreed to the creation of a Stripe Account 2 - Already have a StripeID associated with their account 3 - Still have a Stripe parameter set to False.

    cookie_data = is_registered()

    full_data_user = id_query(int(cookie_data))


    if not full_data_user: return "Error with user identification within the database", 500

    if not full_data_user[7] and full_data_user[8]: # Checking if the user has their "Stripe" column set as False, and if they already have a stripe ID.


        account_link = stripe.AccountLink.create( # Redirecting the user to the Stripe onboarding process.

            account=full_data_user[8], # User's Stripe account ID.
            refresh_url="https://synovial-wilton-unspilt.ngrok-free.dev/refresh-on-board-route", # Where Stripe redirects the user if the Account Link URL has expired or is otherwise invalid.
            return_url="https://synovial-wilton-unspilt.ngrok-free.dev/upload", # Where Stripe redirects the user after they have completed or left the onboarding flow.
            type="account_onboarding",

        )

        return redirect(account_link["url"])


    else: return "There was a problem with Stripe registration. Maybe you've already created a Stripe account before, or trying to access this page by typing the URL manually.", 500


@app.route("/refresh-on-board-route")
def refresh_onboarding(): # For regenerating the link if it's invalid.

    cookie_data = is_registered()

    full_data_user = id_query(int(cookie_data))

    if not full_data_user: return redirect("/login")


    account_link = stripe.AccountLink.create( # Pls read documentation on this!!!!!!!

        account=full_data_user[8],
        refresh_url="https://synovial-wilton-unspilt.ngrok-free.dev/refresh-on-board-route",
        return_url="https://synovial-wilton-unspilt.ngrok-free.dev/upload",
        type="account_update",

    )


    return redirect(account_link["url"])


@app.route("/user-profile", methods=["GET", "POST"])
def user_profile(): # Will be responsible for showing user's profile. (And the possibility to modify it).

    cookies = is_registered()

    if not cookies: return redirect("/login")

    user_data = id_query(int(cookies))

    restrict_access_to_details(user_data)

    #---- User's data ----#

    user_pfp = user_data[6] # Getting user's profile picture using this index.

    first_name = user_data[1]

    last_name = user_data[2]

    has_2fa = user_data[9]  # This index is a Boolean, indicating whether the user has 2-factor-authentication.

    night_mode = user_data[10]

    if request.method == "POST":

        user_pfp_new = request.files.get("new-pfp-user") # In order to get <FileStorage>.

        # File security measures:

        secure_filename(user_pfp_new.filename)

        if check_file_allowed(user_pfp_new.filename) and not exceeds_file_size_limit(user_pfp_new, 1500000) and check_image_content(user_pfp_new) and image_decode(user_pfp_new):

            user_pfp_new = image_re_encode(user_pfp_new)

            upload_result = cloud_upload.upload(user_pfp_new)

            with engine.connect() as connection:

                connection.execute(

                    customer_table.update().where(customer_table.c.ID == user_data[0]).values(ProfilePicture=upload_result["secure_url"])

                )

                connection.commit()

        return redirect("/user-profile")


    return render_template("user.html", user_curr_pfp=user_pfp, night_mode=night_mode, first_name=first_name, last_name=last_name, has_2fa=has_2fa)


@app.route("/toggle-theme")
def switch_color_mode(): # Dedicated to switching the color mode.

    cookies = is_registered()

    if not cookies: return redirect("/login")

    user_dark_mode_info = id_query(int(cookies))[10] # Getting user's night mode setting.

    # Switching dark mode to True/False, depending on user's preferences.

    with engine.connect() as connection:

        connection.execute(

            customer_table.update().where(customer_table.c.ID == cookies).values(Night_mode=not user_dark_mode_info) # Switching to the opposite of the user's settings

        )

        connection.commit()

    return redirect("/user-profile")


@app.route("/generate-2fa", methods=["GET", "POST"])
def generate_2fa(): # Will be responsible for generating user's 2FA.

    if not is_registered(): return redirect("/login")

    user_cookie = is_registered()

    user_data = id_query(user_cookie)

    restrict_access_to_details(user_data)

    if user_data[11]: return redirect("/") # If the user's manually typing the URL, trying to create 2FA. (There's another URL that's meant for resetting 2FA).


    encr_tool = ChaCha20Poly1305(b64decode(os.getenv("SECRET_ENCRYPTION_KEY")))

    if not user_data[13]: # Trying to access user's temporary key.

        # Creating a new key with random_base32()

        key = pyotp.random_base32()

        # Encrypting them, so the keys are not "naked" in the DB.

        nonce = os.urandom(12) # Generating a random 12-bytes-long number.

        encr_key = encr_tool.encrypt(nonce, key.encode("utf-8"), associated_data=user_data[0].to_bytes()) # Associated_data - per user "salt" => more security.

        # Filling a "Temp_key" Column.

        with engine.connect() as connection:

            connection.execute(

                customer_table.update().where(customer_table.c.ID == user_cookie).values(Temp_key=encr_key, Nonce=nonce)

            )

            connection.commit()

        # The reason I'm doing this is that I don't have to regenerate user's key on every single "GET" request => impossible to verify, whether the user's typed a correct 2FA key or a wrong one.

    user_data_updated = id_query(user_cookie) # I fetch the data again.

    # This is done because, if the user accessed the page for the first time, then a new key will be generated and committed into the DB, thus, making previous data record obsolete.

    # That will lead to nonce not being fetched properly.

    user_encr_key = user_data_updated[13]

    user_nonce = user_data_updated[12]

    # Decrypting user's key.

    decrypted_key = encr_tool.decrypt(user_nonce, user_encr_key, associated_data=user_data[0].to_bytes())

    # Generating a URL using the key.

    decrypted_utf = decrypted_key.decode("utf-8")

    totp_user_url = pyotp.totp.TOTP(decrypted_utf).provisioning_uri(name=f"{user_data[1]} {user_data[2]}",
                                                          issuer_name="BlueMark")

    qr_code_img: Image.Image = qrcode.make(totp_user_url) # Specifying the exact data type that this variable should have (type hint/type notations).

    # This is done so that this variable has a function .save()

    # Creating a BytesIO object.

    img_buffer = BytesIO()

    qr_code_img.save(img_buffer, format="PNG")

    img_buffer.seek(0) # Return to the beginning of the image.

    img_data = img_buffer.getvalue()

    # Encoding the image.

    encoded_img = b64encode(img_data).decode("utf-8")

    # Creating link for the HTML type:

    img_link = f"data:image/png;base64, {encoded_img}"

    if request.method == "POST":

        # Getting user's inputted full code.

        full_code = f"{request.form.get('num1')}{request.form.get('num2')}{request.form.get('num3')}{request.form.get('num4')}{request.form.get('num5')}{request.form.get('num6')}"

        # Not the cleanest code... :(

        # Verifying user's code.

        verify_totp = pyotp.TOTP(decrypted_utf).verify(full_code)


        if verify_totp:

            with engine.connect() as connection:

                # Setting user's 2FA boolean to True, promoting a previously temporary key to the status of a primary one.

                # Deleting the temporary key.

                connection.execute(

                    customer_table.update().where(customer_table.c.ID == user_data[0]).values(TwoFA=True, Encrypted_secret=user_encr_key, Temp_key=None) # Basically deleting Temp_key.

                )

                connection.commit()

            return redirect("/recovery-codes")

        else: # If the user has submitted an incorrect authentication code.

            return render_template("two-factor.html", qr_img=img_link, error_code=True, night_mode = user_data[10])


    return render_template("two-factor.html", qr_img=img_link, error_code=False, night_mode = user_data[10])


@app.route("/generate-2fa/manual", methods=["GET", "POST"])
def generate_2fa_manually(): # If the user decided to enter the 2FA code manually. (Maybe they're on the phone, or can't scan the QR code for some reason).


    if not is_registered(): return redirect("/login")

    user_cookie = is_registered()

    user_data = id_query(user_cookie)

    restrict_access_to_details(user_data)


    user_encr_key = user_data[13]

    user_nonce = user_data[12]

    if user_data[11]: return redirect("/")

    if not user_encr_key and not user_nonce: return redirect("/generate-2fa")

    # Generating random key for TOTP.

    encr_tool = ChaCha20Poly1305(b64decode(os.getenv("SECRET_ENCRYPTION_KEY")))

    # Decrypting user's key.

    decrypted_key = encr_tool.decrypt(user_nonce, user_encr_key, associated_data=user_data[0].to_bytes())

    # Generating a URL using the key.

    key = decrypted_key.decode("utf-8")


    if request.method == "POST":

        full_code = f"{request.form.get('num1')}{request.form.get('num2')}{request.form.get('num3')}{request.form.get('num4')}{request.form.get('num5')}{request.form.get('num6')}"

        verify_totp = pyotp.TOTP(key).verify(full_code)

        if verify_totp:

            with engine.connect() as connection:

                # Setting user's 2FA boolean to True, promoting a previously temporary key to the status of a primary one.

                # Deleting the temporary key.

                connection.execute(

                    customer_table.update().where(customer_table.c.ID == user_data[0]).values(TwoFA=True, Encrypted_secret=user_encr_key, Temp_key=None)

                )

                connection.commit()

            return redirect("/recovery-codes")

        else:

            return render_template("two-factor-manual.html", secret_32=key, error_code_manual=True, night_mode = user_data[10])


    return render_template("two-factor-manual.html", secret_32=key, error_code_manual=False, night_mode = user_data[10])


@app.route("/recovery-codes")
def generate_recovery(): # Will be responsible for generating 2FA recovery codes after the user's completed the main 2FA process.

    user_cookie = is_registered()


    if not user_cookie: return redirect("/login")


    user_data = id_query(int(user_cookie))


    if user_data[14]: return redirect("/") # If the user already has recovery codes.

    all_users_codes = generate_2fa_recovery_codes()

    hash_and_commit_recovery_codes(all_users_codes, int(user_cookie))

    return render_template("recovery_codes.html", all_recovery_codes=all_users_codes, night_mode = user_data[10])


@app.route("/reset-2fa/<from_login>", methods=["GET", "POST"]) # from_login is a boolean that indicates whether the user came from the login page. (The differences being: how I fetch user's ID, and what I do after resetting their 2FA settings.)
def reset_2fa(from_login): # Will generate a simple form, where the user can input a secret recovery code that I showed to them when they've initially installed 2FA on their account.

    if from_login == "True":

        user_id = session["temp_user_id"]  # In case the user came from the login page.

    else:

        user_id = is_registered()


    user_data = id_query(int(user_id)) # Just in case convert the user_id to an integer... :D


    if from_login != "True": night_mode = user_data[10] # If the user came from their profile page.

    else: night_mode = False # If from the login page.


    user_recovery_codes = user_data[14]

    if not user_recovery_codes: return redirect("/") # If user's account doesn't have a single recovery code.


    if request.method == "POST":

        user_input_code = request.form.get("recovery_code")

        if check_recovery_codes(all_recovery_codes=user_recovery_codes, user_code_hash=user_input_code):

            with engine.connect() as connection:

                # Resetting user's 2FA parameters if the recovery code succeeds

                connection.execute(

                    customer_table.update().where(customer_table.c.ID == user_id).values(TwoFA=False, Encrypted_secret=None, Nonce=None, Recovery_codes=None)

                )

                connection.commit()

            if from_login == "True":

                session.clear()  # Resetting the session.

                resp = make_response(redirect("/"))

                two_m_exp = timedelta(days=60) + datetime.now()  # Setting the expiration date for cookies at 2 months.

                resp.set_cookie(key="saved_cookies", value=serializer.dumps({"user_id": str(user_id)}), httponly=True,
                                samesite="Lax", secure=True, partitioned=True, expires=two_m_exp)

                return resp

            else: return redirect("/user-profile")


        else:

            return render_template("input_recovery_codes.html", code_error=True, from_login=from_login, night_mode=night_mode)

    return render_template("input_recovery_codes.html", code_error=False, from_login=from_login, night_mode=night_mode)


@app.route("/reauthorization", methods=["GET", "POST"])
def reauthorization_page(): # Will be responsible for checking user's credentials before letting them change their profile data. (Stuff like 2FA, password, etc.)

    user_cookie = is_registered()


    if not user_cookie: return redirect("/login")


    user_data = id_query(int(user_cookie))

    user_hash_password = user_data[4]

    has_2fa = user_data[9]

    if user_hash_password == "google": # In case the user's registered with Google.

        if has_2fa: return redirect("/reauthorize-2fa")

        else:

            give_permission_to_details(user_data)

            return redirect("/change-details")

    if request.method == "POST":

        # Hash the password, check if the user has the same password hash as in his cookies.

        # If it is - check if they have 2FA installed.

        # If they do - then render the 2FA page, asking the user to type the code from the authenticator app.

        # If they don't - simply render the credentials change page.

        user_authorize_password = request.form.get("password-field-authorize")

        try:

            hasher.verify(password=user_authorize_password, hash=user_hash_password)


            if has_2fa: return redirect("/reauthorize-2fa")

            else:

                give_permission_to_details(user_data)

                return redirect("/change-details")


        except argon2.exceptions.VerifyMismatchError:

            return render_template("reauthorization_credentials.html", login_info=True)


    return render_template("reauthorization_credentials.html", login_info=False)


@app.route("/reauthorize-2fa", methods=["GET", "POST"])
def reauthorize_2fa():

    user_cookie = is_registered()


    if not user_cookie: return redirect("/login")


    user_data = id_query(int(user_cookie))


    encr_tool = ChaCha20Poly1305(b64decode(os.getenv("SECRET_ENCRYPTION_KEY")))


    user_encr_key = user_data[11]

    user_nonce = user_data[12]

    # Decrypting user's key in order to verify it during POST request.

    decrypted_key = encr_tool.decrypt(user_nonce, user_encr_key, associated_data=user_data[0].to_bytes())

    # Decoding from UTF-8.

    decrypted_utf = decrypted_key.decode("utf-8")


    if request.method == "POST":

        full_code = f"{request.form.get('num1')}{request.form.get('num2')}{request.form.get('num3')}{request.form.get('num4')}{request.form.get('num5')}{request.form.get('num6')}"

        # Verifying user's code.

        verify_totp = pyotp.TOTP(decrypted_utf).verify(full_code)

        if verify_totp:

            give_permission_to_details(user_data)

            return redirect("/change-details")

        else: return render_template("two-factor-reauthorize.html", error_code=True, night_mode=user_data[10])


    return render_template("two-factor-reauthorize.html", error_code=False, night_mode=user_data[10])


@app.route("/change-details", methods=["GET", "POST"])
def change_details(): # Responsible for letting the user change their account details (protected using can_access_credentials)

    user_cookie = is_registered()

    registered_with_google = False

    same_password = True # Will determine if I'll hash user's password.

    if not user_cookie: return redirect("/login")


    user_data = id_query(int(user_cookie))


    # Fetching all the current user's data

    user_current_fname = user_data[1]

    user_current_lname = user_data[2]

    user_current_email = user_data[3]

    user_current_password = user_data[4]

    night_mode = user_data[10]


    if user_current_password == "google": registered_with_google = True


    if not user_data[15]: return redirect("/") # If the user doesn't have a permission to access the data.

    if request.method == "POST":

        fname_update = request.form.get("fname-field-register")

        lname_update = request.form.get("lname-field-register")

        if not registered_with_google:

            email_update = request.form.get("email-field-register")

            potential_password_update = request.form.get("password-field-register")

            if not potential_password_update:

                password_update = user_data[4]  # Setting user's previous password if they haven't changed it.

            else:

                password_update = potential_password_update  # Else - setting the new value.

                same_password = False


        else: # If the user's registered with Google previously.

            email_update = user_data[3]

            password_update = user_data[4]


        # Checking whether the user's changed at least a single input, if not - redirect back to the page.

        # Not the cleanest code :(

        # Very many not the cleanest code :((


        if fname_update == user_current_fname and lname_update == user_current_lname and email_update == user_current_email and password_update == user_current_password:

            return render_template("change_credentials.html", error=False, error_no_change=True, fname=user_data[1], lname=user_data[2], email=user_data[3], password=user_data[4], google=registered_with_google, night_mode=night_mode)

        else: # If the user's changed at least one input field.

            # Checking if user's (potentially) new email's appeared is already in the DB.

            potential_user = email_query(email_update)

            if potential_user and potential_user[0] != int(user_cookie): # Then the user's trying to change their email to the one that someone already owns.

                return render_template("change_credentials.html", error=True, error_no_change=False, fname=user_data[1], lname=user_data[2], email=user_data[3], password=user_data[4], google=registered_with_google, night_mode=night_mode)


            else: # If the user's changed at least one input field, and their email is either the same, or a new that no one else has on the website.

                if not registered_with_google and not same_password: password_update = hasher.hash(password_update)

                # Hashing user's new password if they didn't register with Google, and if they changed their password.


                with engine.connect() as connection:

                    connection.execute(

                        customer_table.update().where(customer_table.c.ID == user_data[0]).values(FirstName=fname_update, LastName=lname_update, Password=password_update, Email=email_update)

                    )

                    connection.commit()

                return redirect("/user-profile")


    return render_template("change_credentials.html", error=False, error_no_change=False, fname=user_data[1], lname=user_data[2], email=user_data[3], password=user_data[4], google=registered_with_google, night_mode=night_mode)


def item_status(): # Will be responsible for displaying the status of various products. (The status itself won't change, but it'll be pretty cool still).

    pass


@app.route("/logout")
def logout():

    resp = make_response(redirect("/"))

    if not is_registered():  # If user's trying to log out... without having an account to log out from.

        return redirect("/login")  # Then sending them to the login page if they're not registered.

    else:

        resp.delete_cookie("saved_cookies", secure=True, httponly=True, partitioned=True, samesite="Lax")

        return resp


@app.route("/delete-account-prompt", methods=["GET", "POST"])
def delete_account():

    user_cookies = is_registered()


    if not user_cookies: return redirect("/login") # At first checking if the user's even registered.

    user_data = id_query(int(user_cookies))

    if not user_data[15]: return redirect("/change-details") # Then checking if they have Can_access_credentials flag set to True.

    night_mode = user_data[10]

    if request.method == "POST": # TODO: delete all the products that are related to the user!

        with engine.connect() as connection:

            connection.execute(

                customer_table.delete().where(customer_table.c.ID == user_cookies)

            )

            connection.commit()

        # Deleting user's cookies.

        resp = make_response(redirect("/"))

        resp.delete_cookie("saved_cookies", secure=True, httponly=True, partitioned=True, samesite="Lax")

        return resp

    return render_template("delete_prompt.html", night_mode=night_mode)


if __name__ == "__main__":

    app.run(debug=True, port=3000)
