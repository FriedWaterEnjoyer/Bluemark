// The main purpose of this file is to disable the "Delete Review" Button in the reviews.html.

// Getting the button itself.

let deleteReviewButton = document.getElementsByClassName("delete-review-button")[0];

document.addEventListener("DOMContentLoaded", (event) => {

    if (deleteReviewButton) {

        deleteReviewButton.addEventListener("click", () => {

            deleteReviewButton.classList.add("inactive");

        });

    }

});
