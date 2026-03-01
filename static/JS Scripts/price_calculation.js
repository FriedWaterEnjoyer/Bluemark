// The main point of this file is to calculate the price of the individual items in the cart. (And let the user increase it using plus and minus signs).

async function updateCart(itemId, actionType) {

/*

This function takes two inputs:

itemId (speaks for itself);

actionType (can be: "plus", "minus" or "del". Takes part in determining the final price and regulating the quantity);

Gets triggered whenever the user's pressing the plus/minus SVGs or the trashcan SVG.

*/


    try {

        const response = await fetch(

        "/api/calculate-price",

        {

            method: "POST",

            headers: {

                "Content-Type": "application/json",

            },

            body: JSON.stringify({id: itemId, action: actionType})

        });

        if (!response.ok) {

            throw new Error("Something's not ok :(");

        }

        const data = await response.json()

        return data["total"] // Returns the new total calculated on the Python backend and the new quantity.

        // Update the DOM here.

    } catch (error) {

        console.error("Problem: ", error);

    }

}


// HTMLCollection(-s) of all the necessary elements. (Needed for indexing).
const allNumberRegulators = document.getElementsByClassName("quantity-number");
const allPlusButtons = document.getElementsByClassName("plus-button");
const allMinusButtons = document.getElementsByClassName("minus-button");


const totalElement = document.getElementById("text-total");


const checkoutButton = document.getElementsByClassName("checkout-button")[0]; // In order to set it to inactive if there are not items in the cart. (Used only in "del" method).


async function checkQuantity(actionTypeButton, itemId, button) { // Activates when the user's pressing one of the quantity-regulators (minus and plus). It checks whether the user can change the quantity of the item. (No less than 1, but no more than 3).
// Also triggers an updateCart() function if all the criteria is met.
// actionTypeButton - can be "plus", "minus" or "del".
// cardId - mostly to just point out in which card the quantity change needs to happen.


    let previousTotalPrice = document.getElementById("text-total");

    previousTotalPrice = previousTotalPrice.textContent;

    previousTotalPrice = parseFloat(previousTotalPrice.split("$")[1]); // In order not to include the dollar sign.


    let mainCard = button.closest(".card") // Find the closest element that matches the CSS selector ".card".

    let numberRegulator = mainCard.querySelector(".quantity-number");

    let numberCheck = numberRegulator.textContent; // For looking up the quantity of the individual item. (And replace the old value of the quantity).

    let plusButton = mainCard.querySelector(".plus-button");

    let minusButton = mainCard.querySelector(".minus-button");


    if (actionTypeButton === "plus") { // If the user's trying to add one more item to the cart.

        plusButton.classList.add("inactive");

        minusButton.classList.add("inactive");

        if (numberCheck === 3) {

            return // pass, since the maximum amount of items has been reached.

        }


        numberCheck++; // Updating the quantity of the item if the termination conditions aren't met.

        let newTotalPrice = await updateCart(itemId, "plus"); // Updating the cart with "plus" as the action.

        totalElement.textContent = `$${newTotalPrice}`; // Updating the frontend price.

        numberRegulator.textContent = numberCheck; // Changing the frontend text.

        plusButton.classList.remove("inactive");

        minusButton.classList.remove("inactive");


        if (numberCheck === 3) {

            plusButton.classList.add("inactive"); // Disabling the button if the count reaches 3.

        }

    }

    else if (actionTypeButton === "minus") {

        plusButton.classList.add("inactive");

        minusButton.classList.add("inactive");

        if (numberCheck === 1) {

            return // pass for the same reason as "=== 3" condition above.

        }

        numberCheck--;

        let newTotalPrice = await updateCart(itemId, "minus");

        totalElement.textContent = `$${newTotalPrice}`;

        numberRegulator.textContent = numberCheck;

        plusButton.classList.remove("inactive");

        minusButton.classList.remove("inactive");


        if (numberCheck === 1) { // If the amount of items is equal to 1.

            minusButton.classList.add("inactive");

        }

    }

    else if (actionTypeButton === "del") { // If the user wants to delete something from their cart.

        let newTotalPrice = await updateCart(itemId, "del"); // No need to check anything, just send the request to the server.

        mainCard.remove(); // Deleting the element.

        totalElement.textContent = `$${newTotalPrice}`; // Changing the price.


        if (newTotalPrice === "0.00") { // Adding "inactive" class to the checkout button if the total price of all the items is equals to 0.

            // Since, in that case, the amount of items in user's cart is 0 - then the checkout button must be disabled.

            checkoutButton.classList.add("inactive");

        }

    }

    else {

        // pass - since, most likely, the user's changed the content of the onclick. (I'll prolly never use it after this project... Too risky and unsafe).

    }


}

function checkQuantityOnLoad() { // Simply checks which svg (plus/minus) buttons need to be given the class of .inactive when the page loads. (Runs only once).

    for (let i = 0; i < allNumberRegulators.length; i++) {

        if (allNumberRegulators[i].textContent === "1") {

            allMinusButtons[i].classList.add("inactive");

        }

        if (allNumberRegulators[i].textContent === "3") {

            allPlusButtons[i].classList.add("inactive");

        }

    }

}

function disableCheckoutIfPayment() { // The main purpose of this function is to disable the checkout button after the user clicks on it. (This is done so that users won't bombard the server with requests).

    checkoutButton.disabled = true;

}

document.addEventListener("DOMContentLoaded", (event) => { // Calling the checkQuantityOnLoad as soon as the page loads.

    checkQuantityOnLoad();

});
