// The main purpose of this file is to disable the heart SVG button on the main page when the user clicks on it.

// Getting all the buttons (both for mobile and PC).


// For PC.

let allLikedButtons = document.querySelectorAll(".heart-button");

let allRemoveLikedButtons = document.querySelectorAll(".heart-button-liked-main");

// For mobile.

let allLikedButtonsMobile = document.querySelectorAll(".heart-button-mobile");


document.addEventListener("DOMContentLoaded", (event) => {

     allLikedButtons.forEach(likedButtonMain => {

        likedButtonMain.addEventListener("click", () => {

            likedButtonMain.classList.add("inactive");

        })

     });


     allRemoveLikedButtons.forEach(removeLikedButtonMain => {

        removeLikedButtonMain.addEventListener("click", () => {

            removeLikedButtonMain.classList.add("inactive");

        })

     })

     allLikedButtonsMobile.forEach(likedButtonMobile => {

        likedButtonMobile.addEventListener("click", () => {

            likedButtonMobile.classList.add("inactive");

        })

     });

});

// I didn't cook with this one...
