// The main purpose of this file is to show the rest of the form (i.e., delivery tracking number) once the merchant clicks on the "Delivering" button.


let deliveryButton = document.getElementsByClassName("delivering-button")[0]; // Fetching the button using its class name.

let trackingNumberInput = document.getElementsByClassName("tracking-number-input")[0]; // Same with the tracking number input.

let submitTrackingNumber = document.getElementsByClassName("submit-tracking")[0]; // Same with the submit input.


deliveryButton.addEventListener("click", function() {

    trackingNumberInput.classList.remove("hidden");

    submitTrackingNumber.classList.remove("hidden");

});
