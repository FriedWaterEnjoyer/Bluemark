document.addEventListener("DOMContentLoaded", () => {

    let googleButton = document.getElementById("google-login-link");

    let registerForm = document.getElementById("register-form");

    let submitButton = document.getElementById("sign-submit");


    googleButton.addEventListener("click", () => {

        googleButton.style.pointerEvents = "none";

        googleButton.style.cursor = "default";

    });

    registerForm.addEventListener("submit", () => {

        submitButton.disabled = true;

    });

});
