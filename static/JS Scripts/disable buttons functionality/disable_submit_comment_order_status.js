document.addEventListener("DOMContentLoaded", () => {


    // For the comment part:

    let merchantCommentForm = document.getElementsByClassName("merchant-comment-form")[0];

    let submitCommentInput = document.getElementsByClassName("submit-input")[0];

    // For the Delivery change part:

    let deliveryForm = document.getElementsByClassName("delivery-details-form")[0];

    let trackingSubmitInput = document.getElementsByClassName("submit-tracking")[0];


    merchantCommentForm.addEventListener("submit", () => {

        submitCommentInput.classList.add("inactive");

    });

    deliveryForm.addEventListener("submit", () => {

        trackingSubmitInput.classList.add("inactive");

    });

});
