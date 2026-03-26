// The purpose of this file is to disable the "Add to cart" and "Liked Items" buttons after the user's pressed them and the redirection has begun.

// Getting both buttons.

let cartButton = document.getElementsByClassName("add-to-cart")[0];

let likedButton = document.getElementsByClassName("add-to-liked")[0];


cartButton.addEventListener("click", function() {

    cartButton.disabled = true;

});


likedButton.addEventListener("click", function() {

    likedButton.disabled = true;

});
