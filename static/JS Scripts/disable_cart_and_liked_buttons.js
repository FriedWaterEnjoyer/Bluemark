// The purpose of this file is to disable the "Add to cart" and "Liked Items" buttons after the user's pressed them and the redirection has begun.

// Getting both buttons.

let cartButton = document.getElementsByClassName("add-to-cart")[0];

let likedButton = document.getElementsByClassName("add-to-liked")[0];

// Getting the success messages that appear when the user ads to the cart/likes the item.

let cartSuccessMessage = document.getElementsByClassName("cart-success-message")[0];

let likedSuccessMessage = document.getElementsByClassName("liked-success-message")[0];


cartButton.addEventListener("click", function() {

    cartButton.disabled = true;

    cartButton.classList.add("inactive");

    cartSuccessMessage.classList.remove("hidden");

});


likedButton.addEventListener("click", function() {

    likedButton.disabled = true;

    likedButton.classList.add("inactive");

    likedSuccessMessage.classList.remove("hidden");

});
