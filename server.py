# TODO: pls create multiple subdivisions of functions (e.g. PasswordManager, TableCreation, DB_Setup, etc.), the lag is just too much, and one 700+ lines python file is not good too :3

# I'll prolly do it closer to the end of the production, for now I want to have everything in one file.

#---- Imports ----#


import os
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, request, make_response, url_for, jsonify
from sqlalchemy import Text, Numeric, Integer, BOOLEAN, ARRAY, create_engine, MetaData, Column, Table  # For DB interactions.
from sqlalchemy.orm import sessionmaker
import argon2 # For hashing passwords.
from authlib.integrations.flask_client import OAuth # For authorization with Google.
from datetime import datetime, timedelta
import stripe # For payment processing. (Using offline API Key, because I can't get it working with online version :3)
import cloudinary # Cloud for storing images and videos.
import cloudinary.uploader as cloud_upload


# !!!!!! Important information !!!!!!

# Please register in ngrok.com and then run these two commands:


# pip3 install ngrok; - for installation.

# ngrok http 3000; - After running localhost (pressing the "run" button), in order for upload page and Stripe API's onboarding process to work properly.

# Then use the ngrok's live link to access the website (i.e., https://synovial-wilton-unspilt.ngrok-free.dev/).

# Otherwise upload page, and all of its functionality, simply won't work.


#---- Password Hasher initialization ----#


hasher = argon2.PasswordHasher(  # Hashing user's password.

    time_cost=3,  # Number of iterations.
    memory_cost=102400,  # 100 Mb in KiB.
    parallelism=8,  # Number of parallel threads.
    hash_len=32,  # Hash's length in bytes.
    type=argon2.Type.ID, # Using Argon2id version. (Most efficient, since it combines benefits of both Argon2d and Argon2i)

)


#---- App + Database + Stripe + Cloudinary Initialization ----#


# Loading .env

load_dotenv()


#---- App Initialization ----#


app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")


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
    Column("InCartAmount", Integer, nullable=True), # Will store the amount of items the user has in his cart. (Needed for the circle around the cart's SVG).
    Column("ProfilePicture", Text, nullable=True),
    Column("Stripe", BOOLEAN, nullable=False),
    Column("Stripe_ID", Text, nullable=True)
    #Column("UserProducts", ARRAY(Integer), nullable=True) - pointing to the IDs of all the products the user has. Don't forget to set it to []!
    #Column("UserVideos", ARRAY(Integer), nullable=True), - for IDs of user's videos.
    #Column("2FA", bool, nullable=False), - for the two-factor authentication.
    #Column("night-mode", bool, nullable=False),

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
    Column("OwnerID", Integer, nullable=False),

)

# TODO: let the user search for every item in a certain category in the product_page.

# TODO: a table with all of the user's purchases.

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


# Cookie Management.


def is_registered(): # Checks if the user's registered.

    # Returns the cookie.

    # If the cookie hasn't been set - returns None.

    # Else - returns the ID of the user.

    saved_cookie = request.cookies.get("saved_cookies")

    return saved_cookie


def email_query(email: str): # In order to query the user by their email.

    return session_db.query(customer_table).where(customer_table.c.Email == email).first()


def id_query(id_input: int): # Does the same as the function above, but with an ID.

    return session_db.query(customer_table).where(customer_table.c.ID == id_input).first()


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


@app.route("/like/<int:product_id>") # This route is responsible for adding a specific item to the user's "liked" pool.
def add_to_liked(product_id):

    user_cookies = request.cookies.get("saved_cookies")

    user_data_liked = id_query(int(user_cookies))

    # If the user's not registered or this item is already in the "liked_items" - then redirect him to the main page.

    if not is_registered() or product_id in user_data_liked[5]: return redirect("/")

    # If none of this returns True - then adding an ID of the product to the liked items of the user.

    user_data_liked[5].append(product_id)

    return redirect("/")


@app.route("/")
def main_page(): # Speaks for itself.

    has_cookies = is_registered() # Checks user's browser for cookies. The HTML pages will change depending on the content of the variable.

    if has_cookies:

        user_data = id_query(int(has_cookies)) # Fetching all the data about the user, utilizing his ID.

    else:

        user_data = None # In case has_cookies is None - then pass in the user's data as None too.


    return render_template(

                            "index.html",

                           registered=has_cookies,

                           user_data=user_data,

                           liked_products=["B","B","B","B"],

                           in_cart_products=["B","B","B","B","B","B"],

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

                resp = make_response(redirect("/"))

                two_m_exp = timedelta(days=60) + datetime.now()  # Setting the expiration date for cookies at 2 months.

                resp.set_cookie(key="saved_cookies", value=str(query[0]), httponly=True, samesite="Lax", secure=True, partitioned=True, expires=two_m_exp)


                # secure: A boolean flag (True/False) indicating whether the cookie should only be transmitted over a secure HTTPS connection. => set to True - more security.

                # httponly: A boolean flag that, if set to true, makes the cookie inaccessible to client-side scripts (e.g., JavaScript), enhancing security against XSS attacks.

                # samesite: Controls when the cookie is sent with cross-site requests. Common values include Lax, Strict, and None.

                # Lax: Sends cookies with top-level navigations and safe HTTP methods (like GET).

                # partitioned: A flag, indicating that the cookie should be stored using partitioned storage, related to Cookies Having Independent Partitioned State (CHIPS).

                # For better protection against CSRF and XSS attacks + privacy benefits.


                return resp

            except argon2.exceptions.InvalidHashError:

                incorrect_login = True # First breaking point: if the .verify function raises a InvalidHashError, i.e., if a user with this email was found in the database, but the password and the hash of the password didn't match.

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

                "Liked": [],

                "Stripe": False,

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

            "InCartAmount": 0,

            "Liked": [],

            "Stripe": False,

            # Just storing their passwords as "google".

            # The reason that it's not a security threat is because I hash all the passwords, even when the user's trying to log in.

            # And this hash, by design, will never give just the word "google" as a hash result.

        })

        connection.commit()

    query = email_query(user_info["email"])

    resp.set_cookie(key="saved_cookies", value=str(query[0]), httponly=True, samesite="Lax", secure=True, partitioned=True, expires=two_m_exp)

    return resp


def product_page():

    pass


def checkout():

    if not is_registered(): return redirect("/login")

def search():

    pass


@app.route("/upload", methods=["GET", "POST"])
def upload_item():

    user_cookies = request.cookies.get("saved_cookies")


    if not user_cookies: return redirect("/login")


    user_data = id_query(int(user_cookies)) # If the user's registered - then getting all the data from his cookies.

    if not user_data[9]: return render_template("striperequired.html") # If the user doesn't have an ID associated with their account.



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

            else: return render_template("striperequired.html") # But if that list contains some elements - then it means that the user returned to the page while completing onboard.

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

            # Uploading the image to Cloudinary.

            upload_result = cloud_upload.upload(single_img)

            # Adding image link to the list that will be uploaded to the database later on.

            db_upload_images.append(upload_result["secure_url"])


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


    return render_template("upload.html")


@app.route("/stripe_registry")
def stripe_registration(): # Where the user will be redirected to if they clicked "Register in Stripe". The main purpose of this URL - to create user account on stripe (using their ID, passed in the URL) - and then redirect them to onboarding page.

    cookie_data = request.cookies.get("saved_cookies")

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

    cookie_data = request.cookies.get("saved_cookies")

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

    cookie_data = request.cookies.get("saved_cookies")

    full_data_user = id_query(int(cookie_data))


    account_link = stripe.AccountLink.create( # Pls read documentation on this!!!!!!!

        account=full_data_user[9],
        refresh_url="https://synovial-wilton-unspilt.ngrok-free.dev/refresh-on-board-route",
        return_url="https://synovial-wilton-unspilt.ngrok-free.dev/upload",
        type="account_onboarding",

    )


    return redirect(account_link["url"])


def user_profile_edit(): # Will be responsible for showing user's profile. (And the possibility to modify it).

    pass

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


if __name__ == "__main__":

    app.run(debug=True, port=3000)
