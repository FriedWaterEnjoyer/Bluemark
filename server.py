# TODO: pls create multiple subdivisions of functions (e.g. PasswordManager, TableCreation, DB_Setup, etc.), the lag is just too much, and one 700+ lines python file is not good too :3
# Now about 1100+ lines lul.
# Now about 1700+ lines omegalul

# Another TODO: at the end of the production, please categorize JS scripts + css (if possible) into files.

# I'll prolly do it closer to the end of the production, for now I want to have everything in one file.

# TODO: Maybe add a shadow to the search bar..? At least when hovered, because it looks pretty cool :3

#---- Imports ----#


import os
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, request, make_response, url_for, jsonify, session
from sqlalchemy import Text, Numeric, Integer, BOOLEAN, ARRAY, create_engine, MetaData, Column, Table, LargeBinary  # For DB interactions.
from sqlalchemy.orm import sessionmaker
import argon2 # For hashing passwords.
from authlib.integrations.flask_client import OAuth # For authorization with Google.
from datetime import datetime, timedelta # For generating a 2-month expiry for a cookie.
import stripe # For payment processing. (Using offline API Key, because I can't get it working with online version :3)
import cloudinary # Cloud for storing images and videos.
import cloudinary.uploader as cloud_upload
from werkzeug.utils import secure_filename # For preventing directory attacks. (Removes stuff like "/", which can lead to the attackers going up through the directory).
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


# !!!!!! Important information !!!!!!

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
    Column("Liked", ARRAY(Integer), nullable=True), # Will store the IDs of all the items that the user liked.
    Column("InCart", ARRAY(Integer), nullable=True), # Will store all the items the user has in cart.
    Column("ProfilePicture", Text, nullable=True),
    Column("Stripe", BOOLEAN, nullable=False),
    Column("Stripe_ID", Text, nullable=True),
    Column("UserProducts", ARRAY(Integer), nullable=True), # All the products that the user's uploaded.
    Column("UserProductHistory", ARRAY(Integer), nullable=True), # Pointing to all the items that the user's bought.
    Column("UserVideos", ARRAY(Integer), nullable=True), # For IDs of user's videos.
    Column("TwoFA", BOOLEAN, nullable=False), # For the two-factor authentication.
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
    Column("Rating", Numeric, nullable=False),
    Column("Price", Numeric, nullable=False),
    Column("Tags", ARRAY(Text), nullable=False, index=True),
    Column("Reviews", ARRAY(Text), nullable=True),
    Column("Description", Text, nullable=False),
    Column("Images", ARRAY(Text), nullable=False),
    Column("OwnerID", Integer, nullable=False, index=True),

)

# TODO: let the user search for every item in a certain category in the product_page.

# TODO: Create a table called "Videos", where i'll store every video that's been posted on the platform.

# TODO: for late-stage development - create a seed data for the database using bulk_insert()

# In order to let all the users have a data by default when forking my project.

# I think I'll have like 4 products per category, so that index page and search will function properly.

# Hence, it'll prolly has 3 columns. One-to-many relationship.


# Creating all the tables and initiating session.

meta_data_obj.create_all(engine)

Session_db = sessionmaker(bind=engine)

session_db = Session_db()

# session_db.bulk_insert_mappings() !!!!!!!!!!!!!!!!!


#---- Cookie Management. ----#


def is_registered(): # Checks if the user's registered.

    # Returns a cookie.

    # Firstly it fetches a cookie, then it checks its signature since the user can simply change it by either using browser extensions, or simply going to the "application" part and changing it themselves.

    # Since I'm using user's ID that's stored in a cookie to register the user - this means that there's a high risk of one user impersonating another simply by changing their cookies.

    # If a cookie hasn't been set or BadSignature error's raised (i.e., if a user has tampered with a cookie)- returns None.

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


ALL_ALLOWED_EXTENSIONS = ["jpeg", "png", "jpg", "mp4"]

def check_file_allowed(filename: str) -> bool: # This function is responsible for checking if a file sent by the user has correct extension. (JPEG, PNG and .mp4 in my case).

    return "." in filename and filename.split(".", 1)[1].lower() in ALL_ALLOWED_EXTENSIONS

    # Checks if dot is in the name of the file. If it is - then it splits the string from the right (.rsplit) and checks the rightmost side if its extension is allowed.

    # If one of these conditions is not True - then returns False.


def restrict_access_to_details(user_data): # If Can_access_credentials is True - then the function immediately sets it to False (In order to keep user's restriction to the data change page, locking it behind reauthorization).

    # If it's set to False - then it simply does nothing.

    if user_data[19]:

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

        has_2fa = user_data[13]

        night_mode_data = user_data[14]

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

                if not query[13]: # In case the user has no 2FA installed.

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

        if not query[13]: # If the user doesn't have 2FA installed.

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

                "InCart": [],

                "Liked": [],

                "Stripe": False,

                "TwoFA": False,

                "Night_mode": False,

                "Is_verified": False,

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


    if query: # Checking if the user's already registered with their Google account.

        resp.set_cookie(key="saved_cookies", value=serializer.dumps({"user_id": str(query[0])}), httponly=True, samesite="Lax", secure=True, partitioned=True, expires=two_m_exp)

        return resp

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

            "InCart": [],

            "Liked": [],

            "Stripe": False,

            "TwoFA": False,

            "Night_mode": False,

            "Is_verified": False,

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

    user_encrypted_secret, user_encrypted_nonce, user_id = user_data[15], user_data[16], user_data[0]

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


def product_page():

    pass

def search():

    pass


@app.route("/upload", methods=["GET", "POST"])
def upload_item():

    if "temp_user_id" in session: session.clear()

    user_cookies = is_registered()


    if not user_cookies: return redirect("/login")


    user_data = id_query(int(user_cookies))  # If the user's registered - then getting all the data from his cookies.

    restrict_access_to_details(user_data)


    if not user_data[9]: return render_template("striperequired.html", night_mode = user_data[14], registered=user_cookies, user_data=user_data, has_2fa = user_data[13]) # If the user doesn't have an ID associated with their account.



    if not user_data[8]: # If the user does have an ID associated with the account, but doesn't have a Stripe column equal to True - then doing the steps below:

        try: # If the user came back to the page after completing an onboarding process.

            new_account_stripe = stripe.Account.retrieve(user_data[9]) # Getting user's Stripe account using his ID. (Putting it in the try - except statement just in case).


            if not new_account_stripe["future_requirements"]["currently_due"]: # This key has all the necessary information about what the user should complete before uploading items.

                # If this key is empty - then it means that the user just completed the onboarding process - and the Stripe key column's yet to be changed.

                with engine.connect() as connection:

                    connection.execute(

                        customer_table.update().where(customer_table.c.ID == user_cookies).values(Stripe=True) # In that case - setting the Stripe column to True.

                    )

                    connection.commit()

            else: return render_template("striperequired.html", night_mode=user_data[14], registered=user_cookies, user_data=user_data, has_2fa = user_data[13])

            # But if that list contains some elements - then it means that the user returned to the page while completing onboard.

            # In this case - return him to the previous page as they didn't complete the onboarding, which is necessary for the product upload feature.


        except stripe.StripeError as e: # Juuuuuuuuust in case...

            app.logger.error(str(e))

            return "There was a problem with Stripe login. We're sorry for the inconvenience.", 500


    if request.method == "POST": # If the user's completed the form and uploaded all the necessary data.


        product_title = request.form.get("product_name")

        product_descr = request.form.get("product_description")


        if not product_descr: product_descr = "No description provided." # If user left the description field empty - then it's an empty string - in that case submitting "No description provided", which will be passed onto the database.


        product_price = request.form.get("product_price")

        all_product_tags = request.form.getlist("all-tags-upload")

        all_imgs = request.files.getlist("product_img")

        db_upload_images = []

        for single_img in all_imgs:

            # Modifying user's image name by removing any malicious characters within the filename.

            single_img.filename = secure_filename(single_img.filename)

            # Then, using this secured filename, checking if the file has correct extension.

            if check_file_allowed(single_img.filename):

                # If it does - uploading the image to Cloudinary.

                upload_result = cloud_upload.upload(single_img)

                # Adding image link to the list that will be uploaded to the database later on.

                db_upload_images.append(upload_result["secure_url"])


            else: pass # If it doesn't have the right file type - simply not appending it to the final list.


        with engine.connect() as connection:

            connection.execute(product_table.insert(), {

                "Name": product_title,

                "Rating": 0,

                "Price": float(product_price),

                "Tags": all_product_tags,

                "Reviews": [],

                "Description": product_descr,

                "Images": db_upload_images, # TODO: don't forget to check if db_upload_images is None in the product page! (When I'll get to it eventually....)

                "OwnerID": user_cookies,

            })

            connection.commit()


        return jsonify({"redirect": "/"}) # Since I'm modifying formData in the upload.html, I need to upload a JSON.


    return render_template("upload.html", night_mode=user_data[14])


@app.route("/stripe_registry")
def stripe_registration(): # Where the user will be redirected to if they clicked "Register in Stripe". The main purpose of this URL - to create user account on stripe (using their ID, passed in the URL) - and then redirect them to onboarding page.

    cookie_data = is_registered()

    user_full_data = id_query(int(cookie_data))


    if not user_full_data: return "User registration error.", 500 # Throwing an error if the query didn't find any email, related to the user's ID.

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


        return redirect("/onboard") # Redirecting the user to the onboarding URL if everything was successful.


    except stripe.StripeError as e:

        app.logger.error(f"Stripe Registry Failed: {str(e)}")

        return "Error with Stripe account creation", 500


@app.route("/onboard")
def onboard_page(): # Where the user will be redirected if they: 1 - agreed to the creation of a Stripe Account 2 - Already have a StripeID associated with their account 3 - Still have a Stripe parameter set to False.

    cookie_data = is_registered()

    full_data_user = id_query(int(cookie_data))


    if not full_data_user: return "Error with user identification within the database", 500


    if not full_data_user[8] and full_data_user[9]: # Checking if the user has their "Stripe" column set as False, and if they already have a stripe ID.

        account_link = stripe.AccountLink.create( # Then redirecting the user to the Stripe onboarding process.

            account=full_data_user[9], # User's Stripe account ID.
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

        account=full_data_user[9],
        refresh_url="https://synovial-wilton-unspilt.ngrok-free.dev/refresh-on-board-route",
        return_url="https://synovial-wilton-unspilt.ngrok-free.dev/upload",
        type="account_onboarding",

    )


    return redirect(account_link["url"])


@app.route("/user-profile", methods=["GET", "POST"])
def user_profile(): # Will be responsible for showing user's profile. (And the possibility to modify it).

    cookies = is_registered()

    if not cookies: return redirect("/login")

    user_data = id_query(int(cookies))

    restrict_access_to_details(user_data)

    #---- User's data ----#

    user_pfp = user_data[7] # Getting user's profile picture using this index.

    first_name = user_data[1]

    last_name = user_data[2]

    has_2fa = user_data[13]  # This index is a Boolean, indicating whether the user has 2-factor-authentication.

    night_mode = user_data[14]

    if request.method == "POST":

        user_pfp_new = request.files.get("new-pfp-user") # In order to get <FileStorage>

        # File security measures:

        secure_filename(user_pfp_new.filename)

        if check_file_allowed(user_pfp_new.filename):

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

    user_dark_mode_info = id_query(int(cookies))[14] # Getting user's night mode setting.

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

    if user_data[15]: return redirect("/") # If the user's manually typing the URL, trying to create 2FA. (There's another URL that's meant for resetting 2FA).


    encr_tool = ChaCha20Poly1305(b64decode(os.getenv("SECRET_ENCRYPTION_KEY")))

    if not user_data[17]: # Trying to access user's temporary key.

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

    user_encr_key = user_data_updated[17]

    user_nonce = user_data_updated[16]

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

            return render_template("two-factor.html", qr_img=img_link, error_code=True, night_mode = user_data[14])


    return render_template("two-factor.html", qr_img=img_link, error_code=False, night_mode = user_data[14])


@app.route("/generate-2fa/manual", methods=["GET", "POST"])
def generate_2fa_manually(): # If the user decided to enter the 2FA code manually. (Maybe they're on the phone, or can't scan the QR code for some reason).


    if not is_registered(): return redirect("/login")

    user_cookie = is_registered()

    user_data = id_query(user_cookie)

    restrict_access_to_details(user_data)


    user_encr_key = user_data[17]

    user_nonce = user_data[16]

    if user_data[15]: return redirect("/")

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

            return render_template("two-factor-manual.html", secret_32=key, error_code_manual=True, night_mode = user_data[14])


    return render_template("two-factor-manual.html", secret_32=key, error_code_manual=False, night_mode = user_data[14])


@app.route("/recovery-codes")
def generate_recovery(): # Will be responsible for generating 2FA recovery codes after the user's completed the main 2FA process.

    user_cookie = is_registered()


    if not user_cookie: return redirect("/login")


    user_data = id_query(int(user_cookie))


    if user_data[18]: return redirect("/") # If the user already has recovery codes.

    all_users_codes = generate_2fa_recovery_codes()

    hash_and_commit_recovery_codes(all_users_codes, int(user_cookie))

    return render_template("recovery_codes.html", all_recovery_codes=all_users_codes, night_mode = user_data[14])


@app.route("/reset-2fa/<from_login>", methods=["GET", "POST"]) # from_login is a boolean that indicates whether the user came from the login page. (The differences being: how I fetch user's ID, and what I do after resetting their 2FA settings.)
def reset_2fa(from_login): # Will generate a simple form, where the user can input a secret recovery code that I showed to them when they've initially installed 2FA on their account.

    if from_login == "True":

        user_id = session["temp_user_id"]  # In case the user came from the login page.

    else:

        user_id = is_registered()


    user_data = id_query(int(user_id)) # Just in case convert the user_id to an integer... :D


    if from_login != "True": night_mode = user_data[14] # If the user came from their profile page.

    else: night_mode = False # If from the login page.


    user_recovery_codes = user_data[18]

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

    has_2fa = user_data[13]

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


    user_encr_key = user_data[15]

    user_nonce = user_data[16]

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

        else: return render_template("two-factor-reauthorize.html", error_code=True, night_mode=user_data[14])


    return render_template("two-factor-reauthorize.html", error_code=False, night_mode=user_data[14])


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

    night_mode = user_data[14]


    if user_current_password == "google": registered_with_google = True


    if not user_data[19]: return redirect("/") # If the user doesn't have a permission to access the data.

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

    if not user_data[19]: return redirect("/change-details") # Then checking if they have Can_access_credentials flag set to True.

    night_mode = user_data[14]

    if request.method == "POST":

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
