// The main purpose of this file is to disable the cancel-order-button on the frontend whenever the user clicks on it,

// Getting all the buttons.

document.addEventListener("DOMContentLoaded", (event) => {

    let allCancelOrderButtons = document.querySelectorAll(".cancel-order-button");


    allCancelOrderButtons.forEach(cancelButton => {

        cancelButton.addEventListener("click", () => {

            cancelButton.classList.add("inactive");

        })

    })

});
