// The main point of this file is to redirect the user to the "/create-checkout-session" URL when they click the checkout button.


async function checkoutRedirect() {

    let previousTotalPrice = document.getElementById("text-total");

    previousTotalPrice = previousTotalPrice.textContent;

    previousTotalPrice = parseFloat(previousTotalPrice.split("$")[1]);

    if (previousTotalPrice > 0.00) {



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

    } else {

        // pass, since the user's prolly modified the frontend :(

    }

};
