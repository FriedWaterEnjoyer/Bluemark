<h1>BlueMark Marketplace Project</h1>

<div>

  <img src="https://camo.githubusercontent.com/43de341c9b8b09764cc735349316e938d77a1da3751ae8bfaec066e3c3450bec/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f707974686f6e2d3336373041303f7374796c653d666f722d7468652d6261646765266c6f676f3d707974686f6e266c6f676f436f6c6f723d666664643534" alt="Python" data-canonical-src="https://img.shields.io/badge/python-3670A0?style=for-the-badge&amp;logo=python&amp;logoColor=ffdd54" style="max-width: 100%;">

  <img src="https://camo.githubusercontent.com/4e39004843387226e83eaacfb24a8df02adb769152f2f7f3db1926cb04500f6d/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f68746d6c352d2532334533344632362e7376673f7374796c653d666f722d7468652d6261646765266c6f676f3d68746d6c35266c6f676f436f6c6f723d7768697465" alt="HTML5" data-canonical-src="https://img.shields.io/badge/html5-%23E34F26.svg?style=for-the-badge&amp;logo=html5&amp;logoColor=white" style="max-width: 100%;">

  <img src="https://camo.githubusercontent.com/3f1b0ba4fa782af96fd436adcddc8716248a6b5c93d78c8ad742611357bed209/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f637373332d2532333135373242362e7376673f7374796c653d666f722d7468652d6261646765266c6f676f3d63737333266c6f676f436f6c6f723d7768697465" alt="CSS3" data-canonical-src="https://img.shields.io/badge/css3-%231572B6.svg?style=for-the-badge&amp;logo=css3&amp;logoColor=white" style="max-width: 100%;">

  <img src="https://camo.githubusercontent.com/dc050359857b187d9f7a075b1a03dccb9606b32b30f3178a1ba5973ac17d1c08/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f6a6176617363726970742d2532333332333333302e7376673f7374796c653d666f722d7468652d6261646765266c6f676f3d6a617661736372697074266c6f676f436f6c6f723d253233463744463145" alt="JavaScript" data-canonical-src="https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&amp;logo=javascript&amp;logoColor=%23F7DF1E" style="max-width: 100%;">

  <img src="https://camo.githubusercontent.com/95ed43a2ddd5867e86355eaa5b8aa800bf784fa823bf87c48128f9caee4e584d/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f706f7374677265732d2532333331363139322e7376673f7374796c653d666f722d7468652d6261646765266c6f676f3d706f737467726573716c266c6f676f436f6c6f723d7768697465" alt="Postgres" data-canonical-src="https://img.shields.io/badge/postgres-%23316192.svg?style=for-the-badge&amp;logo=postgresql&amp;logoColor=white" style="max-width: 100%;">  

</div>

<hr>

<div>

  <p>BlueMark is a stylized marketplace, the main purpose of which is to create a (hopefully) smooth experience for its customers to buy items from the merchants, and for its merchants to upload their products.</p>

  <br>

  <h3>This website integrates many exetrnal libraries, such as:</h3>

  <ul>

  <li><strong>Stripe</strong>: for a secure money transfer between the user and the merchant. Important note: merchants will have to complete Stripe's onboarding for their IDs to be used as a transfer endpoint.</li>

  <li><strong>Ngrok</strong>: for creating a public URL with HTTPS support, since a lot of essential features will not work if the website's hosted locally, particularly Stripe's onboarding process.</li>

  <li><strong>Cloudinary</strong>: for uploading user's images to the cloud, securely storing them there, and then saving links to these images in the Database. That way, the DB is a lot less bloated and the application is much more scalable, in comparison to storing images (BLOBs) directly in the DB.</li>

  <li><strong>Google Oauth 2.0</strong>: as an additional way for the users to register and login on the website, besides password + email.</li>

  <li><strong>Flask</strong>: for handling essential website features, like routing or template rendering.</li>

  <li><strong>SQLalchemy</strong>: for the application-database interactions.</li>

  <li><strong>PostgreSQL</strong>: as the main Database.</li>

  </ul>
  
</div>

<div>

  <h3>User can:</h3>

  <ol>

  <li>Register and login using either password + email or Google.</li>

  <li>Change their profile picture.</li>

  <li>Swap between dark and night modes.</li>

  <li>Set up a time-based 2FA codes using either a QR-code or, if the user's on mobile, a regular code.</li>

  <li>Reset 2FA if they have at least 1 out of 5 reset codes.</li>

  <li>Change account details if they re-register using their credentials.</li>

  <li>Delete their account. (The application will hard-delete all of the user's data, except the financial one, like user's orders).</li>

  <li>Log out from their account.</li>

  <li>Submit, edit and delete their reviews on various products.</li>

  <li>Add an unlimited amount of products to their liked items list.</li>

  <li>Add up to 120 products to their cart.</li>

  <li>Modify quantity of individual items in their cart (from 1 quan. - minimum to 3 quan. - maximum).</li>

  <li>Delete items from their cart.</li>

  <li>Purchase items from an unlimited amount of merchants with just a single checkout. (The money distribution function was built with multiple merchants in mind).</li>

  <li>Track the delivery of each item.</li>

  <li>Cancel individual orders. (If the delivery status of this item is not "Delivering" or "Delivered").</li>

  <li>Look at their purchase history using the "Finished Deliveries" section.</li>

  <li>Become a merchant by completing Stripe's onboarding and uploading their product using a simple form.</li>

  <li>Delete their products using "Your Products" section.</li>

  <li>Track their customer's orders using "Manage Client Orders" section.</li>

  <li>Cancel customer's order, change its delivery status or add comments to the user.</li>

  <li>Search for products using the search bar at the top. (The application takes into consideration items's: titles, descriptions, their tags, as well as user-provided tags).</li>
    
  </ol>
  
</div>

<hr>

<div>

  <h2>BlueMark Preview:</h2>

  <h4>Screenshots:</h4>

  <img width="1919" height="948" alt="Screenshot 2026-04-30 132739" src="https://github.com/user-attachments/assets/2d1655fe-a1a0-4b8b-b44d-51e17bc00565" />

  <img width="1919" height="945" alt="Screenshot 2026-04-30 132923" src="https://github.com/user-attachments/assets/9b485da3-c074-413d-8d74-d079e78d2da8" />

  <img width="1918" height="948" alt="Screenshot 2026-04-30 132946" src="https://github.com/user-attachments/assets/1cce22fd-5c85-4abf-9479-0514bfe77279" />

  <img width="1919" height="944" alt="Screenshot 2026-04-30 133046" src="https://github.com/user-attachments/assets/4bafa2c9-fd18-41bb-9622-1c6a01b3c94c" />

  <img width="1919" height="946" alt="Screenshot 2026-04-30 133117" src="https://github.com/user-attachments/assets/429cc5ce-7ac4-4c2e-a298-cf811c1424f7" />

  <img width="1919" height="948" alt="Screenshot 2026-04-30 133200" src="https://github.com/user-attachments/assets/d25c6f6a-ab6e-4abf-819e-004a4840723b" />

  <img width="1919" height="947" alt="Screenshot 2026-04-30 133219" src="https://github.com/user-attachments/assets/d9cc5cd4-25b9-482a-b85d-62729d0b4ccd" />

  <img width="1919" height="946" alt="Screenshot 2026-04-30 133554" src="https://github.com/user-attachments/assets/40f8ff4b-2304-4abe-8190-6318e6269d93" />

  <img width="1919" height="947" alt="Screenshot 2026-04-30 133629" src="https://github.com/user-attachments/assets/3003b438-8d50-417a-ba3e-302e25bb15c6" />

</div>

<hr>

<div>

  <h2>Preview Video:</h2>

  <p>Due to how big the video is (853Mb), i've decided to upload it to GitHub's Large Files Storage (LFS).</p>

  <br>
  
  <p>Here's a link to download the video (click "View raw"):</p>

  [BlueMark Preview Video.mp4](https://github.com/FriedWaterEnjoyer/Bluemark/blob/main/BlueMark%20Preview%20Video.mp4)

</div>

<hr>

<div>

  <h2>Installation guide</h2>

  <ol>

  <li>Clone this GitHub repository by typing the following command:

    git clone https://github.com/FriedWaterEnjoyer/Bluemark.git

  </li>

  <li>Create a virtual environment in IDE using this command:

    py -m venv venv

  And then this:
  
    venv\Scripts\activate

  </li>

  <li>And then install the packages using:

    pip3 install -r requirements.txt

  </li>

  <li>Then install one more additional package separately (For securing user-uploaded files):

    pip install python-magic-bin
  
  </li>

  <li>
    
  Then you'll need to set up all the environment variables; here's a quick guide on how to do it:
  
  <ul>

  <li><code>DB_USERNAME</code>, <code>DB_PASSWORD</code>, <code>DB_HOST</code>, <code>DB_PORT</code>, <code>DB_NAME</code> - All of them are your setup variables for the PostgreSQL database. Their names are self-explanatory, so just check your own PostgreSQL app for details.</li>

  <li>
    
  <code>CLIENT_ID</code>, <code>CLIENT_SECRET</code> - both of them are for Google OAuth 2.0 initialization - in order to get them for yourself you'll need to set up your own Google Console.
  
  <a href="https://www.youtube.com/watch?v=wctDfjx4xIw">Here's a pretty good video on how to get them. (The part that you need starts at 9:30 and ends at 14:50)</a>

  <p>
    
  Very important note!!!!!!!
  
  <br>

  In the "Authorized redirect URIs" section paste these 4 URIs:

  <br>

  http://synovial-wilton-unspilt.ngrok-free.dev/authorize/google/register

  <br>

  http://synovial-wilton-unspilt.ngrok-free.dev/authorize/google/login

  <br>

  http://synovial-wilton-unspilt.ngrok-free.dev/reauthorize/google/finish

  <br>

  http://synovial-wilton-unspilt.ngrok-free.dev/reauthorize/google/initial

  <br>

  Instead of the localhost mentioned in the video.
  
  </p>
  
  </li>

  <li>

  <code>SECRET_KEY</code> - your secret key for Flask's app.
    
  </li>

  <li>

  <code>SECRET_KEY_STRIPE</code>, <code>PUBLISHABLE_KEY_STRIPE</code> - both of them can be found in Stripe's dashboard. Both of them will be needed for authentication and configuration of the stripe module. (Pls register your project in Stripe Dashboard first).

  <a href="https://www.youtube.com/watch?v=t0gIem3A8-o">Here's a good video on how to access both of them.</a>
    
  </li>

  <li>

  <code>CLOUDINARY_NAME</code>, <code>CLOUDINARY_API_KEY_REGULAR</code>, <code>CLOUDINARY_API_KEY_SECRET</code> - all three of them are for Cloudinary's authentication.

  <a href="https://www.youtube.com/watch?v=ok9mHOuvVSI">Here's an official Cloudinary video that explains where to find all 3 of these parameters.</a>
    
  </li>

  <li>
    
  <code>SECRET_ENCRYPTION_KEY</code> - needed for b64decode and ChaCha20Poly1305 (encryption for 2FA). Same thing as the app key - strings of characters that (ideally) must be pretty long and complicated so that it'll much harder to crack.
    
  </li>

  <li>

  <code>STRIPE_WEBHOOK_SECRET</code> - the most complicated .env variable:
  
  1 - Go to Stripe Dashboard of your project ;
  
  2 - Navigate to the Webhooks section and create your own webhook (follow video instructions) ;
  
  3 - Make the webhook listen for those 3 events: checkout.session.completed; payment_intent.created; payment_intent.succeeded ;

  4 - Set the Endpoint URL of this webhook to https://synovial-wilton-unspilt.ngrok-free.dev/webhook-money-distribution ;
  
  5 - Paste the "Signing secret" key in this variable.

  <a href="https://www.youtube.com/watch?v=08jLFN8fLIo">Here's a video on how to create webhooks in Stripe.</a>
    
  </li>

  </ul>
  
  </li>

  <li>

  <a href="https://ngrok.com">Then, you'll need to register in ngrok to create a public URL.</a>
    
  </li>

  <li><a href="https://dashboard.ngrok.com/get-started/setup/windows">Then go here in order to add an authentication token</a></li>

  <li>Then start the app locally by hitting the "Play" button or pressing F12</li>

  <li>
    
  Then type in console the following command

    ngrok http 80

  or

    ngrok http 3000

  In order to expose your local file to ngrok.
  
  </li>

  <li>click on the link that'll pop up; it should look something like https://synovial-wilton-unspilt.ngrok-free.dev</li>
  
  </ol>
  
</div>

<p>Thank you for paying attention to my project, i really hope you'll enjoy it <3</p>
