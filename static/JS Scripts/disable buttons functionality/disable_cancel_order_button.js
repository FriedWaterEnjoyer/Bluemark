// The main purpose of this file is to disable the main-cancel-order (subclass of the cancel-order-button) on the frontend whenever the user clicks on it,

// Getting all the buttons.

// It specifically targets the main-cancel-order instead of cancel-order-button, since it'd disable all the buttons that create a popup, whereas this JS file only needs to disable the buttons that trigger the refund/deletion process.

document.addEventListener("DOMContentLoaded", (event) => {

    let allCancelOrderButtons = document.querySelectorAll(".main-cancel-order");


    allCancelOrderButtons.forEach(cancelButton => {

        cancelButton.addEventListener("click", () => {

            cancelButton.classList.add("inactive");

        })

    })

});
