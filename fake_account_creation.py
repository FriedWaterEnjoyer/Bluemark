# The main purpose of this file is to insert 1 fake-test user with Stripe integration, then create 18 products (the amount on the main page) so that the user wouldn't see a lot of placeholders.

# None of the products are for sale.

# Grand majority of the content in these rows was generated using AI.

# This contact is also completely fake :3

class CreateFakeUserAndProducts:

    def __init__(self):

        self.products_to_insert = [
    {
        "name": "Vintage 1970s Acoustic Guitar - Spruce Top",
        "rating": 0,
        "price": 450.00,
        "tags": ["Music", "Art"],
        "description": "A beautifully aged acoustic guitar with a warm, resonant tone. Minor scuffs on the body but plays perfectly. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400", "https://placehold.co/600x400", "https://placehold.co/600x400", "https://placehold.co/600x400", "https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Limited Edition Art Book",
        "rating": 0,
        "price": 45.99,
        "tags": ["Books", "Art", "Anime"],
        "description": "Hardcover collection of concept art. 200 pages of high-quality prints. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Retro Gaming Console",
        "rating": 0,
        "price": 89.50,
        "tags": ["Console"],
        "description": "Classic handheld pre-loaded with 50 indie titles. Features a backlit screen and rechargeable battery. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400", "https://placehold.co/600x400", "https://placehold.co/600x400", "https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Fluffy Totoro Plushie",
        "rating": 0,
        "price": 35.00,
        "tags": ["Plush", "Anime"],
        "description": "Extremely soft and huggable. Perfect for studio Ghibli fans. Brand new with tags. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Abstract Canvas Painting - 'Ocean Dreams'",
        "rating": 0,
        "price": 120.00,
        "tags": ["Art"],
        "description": "Original hand-painted acrylic on canvas. 11x14 inches. Cool blue and teal tones. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400", "https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Suburban 3-Bedroom Estate Property Catalog",
        "rating": 0,
        "price": 15.00,
        "tags": ["Estate", "Books"],
        "description": "Detailed listing brochure for the suburban development. Includes floor plans. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Lo-Fi Beats Vinyl Record - Vol. 1",
        "rating": 0,
        "price": 28.00,
        "tags": ["Music"],
        "description": "Limited edition white vinyl. Perfect for studying or relaxing. Mint condition. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400", "https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Wireless Controller",
        "rating": 0,
        "price": 64.99,
        "tags": ["Console", "Else"],
        "description": "Ergonomic design with haptic feedback. Compatible with most modern consoles and PC. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400", "https://placehold.co/600x400", "https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Handmade Ceramic Succulent Planter",
        "rating": 0,
        "price": 19.99,
        "tags": ["Art", "Else"],
        "description": "Small ceramic pot with a unique speckled glaze. Drainage hole included. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Complete Manga Set: 'Spirit Realm' Vol 1-10",
        "rating": 0,
        "price": 95.00,
        "tags": ["Books", "Anime"],
        "description": "Full first arc of the hit manga series. Books are in great condition, no dog-eared pages. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400", "https://placehold.co/600x400", "https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Electric Keyboard with Weighted Keys",
        "rating": 0,
        "price": 299.00,
        "tags": ["Music", "Console"],
        "description": "88-key digital piano. Includes MIDI output for DAW connectivity. Great for beginners. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400", "https://placehold.co/600x400", "https://placehold.co/600x400", "https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Cute Shiba Inu Round Plush Bolster",
        "rating": 0,
        "price": 22.50,
        "tags": ["Plush"],
        "description": "A long, cylindrical plush pillow shaped like a Shiba Inu. Very squishy. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400", "https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Gothic Architecture Photo Book",
        "rating": 0,
        "price": 55.00,
        "tags": ["Books", "Art", "Estate"],
        "description": "Coffee table book featuring high-resolution photos of European cathedrals. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400", "https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Professional Studio Microphone Kit",
        "rating": 0,
        "price": 149.00,
        "tags": ["Music", "Else"],
        "description": "Condenser mic with pop filter and adjustable arm stand. Ideal for podcasting. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400", "https://placehold.co/600x400", "https://placehold.co/600x400", "https://placehold.co/600x400", "https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Anime Character Enamel Pin Set",
        "rating": 0,
        "price": 12.00,
        "tags": ["Anime", "Art"],
        "description": "Set of 4 high-quality enamel pins featuring various chibi characters. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Luxury Apartment Lease Guide",
        "rating": 0,
        "price": 5.00,
        "tags": ["Estate", "Else"],
        "description": "A digital PDF guide on how to navigate luxury estate rentals in the city. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Classic Wooden Chess Set",
        "rating": 0,
        "price": 39.99,
        "tags": ["Else", "Art"],
        "description": "Hand-carved wooden pieces with a folding magnetic board. Elegant and portable. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400", "https://placehold.co/600x400", "https://placehold.co/600x400"],
        "ownerID": 1
    },
    {
        "name": "Custom Hand-Knit Woolen Octopus",
        "rating": 0,
        "price": 18.00,
        "tags": ["Plush", "Art"],
        "description": "A small, purple knitted octopus. Each one is unique and handmade with love. Contact Alex at alex.market@email.com or 555-0123.",
        "images": ["https://placehold.co/600x400", "https://placehold.co/600x400"],
        "ownerID": 1
    }
]


    def create_user_bulk_insert_products(self, session, engine, customer_table, product_table):

        # Querying the customer_table and product_table tables - if they have at least one row - then it means that the test accounts were already created.

        # In this case don't call the function.

        user_check = session.query(customer_table).where(customer_table.c.ID == 1).first()

        # Querying a product with the ID of 18 (total amount of test products that will be created). If there's no such product - then begin the creation process.

        # If it does - then do nothing.

        product_check = session.query(product_table).where(product_table.c.ID == 18).first()


        if user_check or product_check: pass

        else:

            # Inserting a fake user into the Database.

            with engine.connect() as connection:

                connection.execute(

                    customer_table.insert(), {

                        "FirstName": "Test",

                        "LastName": "Account",

                        "Email": "coolEmail@gmail.com",

                        "Password": "google",

                        "InCartAmount": 0,

                        "ProfilePicture": "https://img.icons8.com/?size=100&id=tZuAOUGm9AuS&format=png&color=000000",

                        "Stripe": True,

                        "Stripe_ID": "acct_1PjK9sR4vNn2Z8xW",

                        "TwoFA": False,

                        "Night_mode": False,

                        "Encrypted_secret": None,

                        "Nonce": None,

                        "Temp_key": None,

                        "Recovery_codes": None,

                        "Can_access_credentials": False,

                        "Is_a_Merchant": True,

                    }

                )

                connection.commit()

            # Inserting all the rows created above.

            with engine.connect() as connection:

                connection.execute(

                    product_table.insert(), self.products_to_insert

                )

                connection.commit()
