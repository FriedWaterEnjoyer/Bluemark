// The main purpose of this file is to show the rest of the form (i.e., delivery tracking number) once the merchant clicks on the "Delivering" button.

document.addEventListener("DOMContentLoaded", (event) => {


    document.querySelectorAll(".delivering-button").forEach(button => { // Querying all the buttons with the class "delivering-button". (Can appear only if order's status is "Processing").

        button.addEventListener("click", () => { // Adding EventListener "click" to each button.

            const parentFormElement = button.closest(".delivery-details-form"); // Looking up the parent element of the button as soon as the user clicks. (In this case it's the form "delivery-details-form").

            // Then removing the "hidden" classes of both the input and submit.

            parentFormElement.querySelector(".tracking-number-input").classList.remove("hidden");

            parentFormElement.querySelector(".submit-tracking").classList.remove("hidden");

        })

    })


});
