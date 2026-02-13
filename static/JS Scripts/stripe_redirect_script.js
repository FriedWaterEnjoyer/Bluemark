// The main point of this file is to redirect the user to the "/create-checkout-session" URL when they click the checkout button.


async function checkoutRedirect() {

    const response = await fetch(

    "/create-checkout-session", {

        method: "POST",

        headers: {

            "Content-type": "application/json"

            }

        }

    )

    const data = await response.json()

    window.location.href = data.url; // Redirecting to Stripe.


};
