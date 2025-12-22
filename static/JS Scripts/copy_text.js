// This JS file is responsible for the functionality of the "copy" SVG in the "two-factor-manual.html"

function copyText() { // The process of copying the text.
    let textElement = document.getElementById('text-to-copy');
    let text = textElement.textContent;

    navigator.clipboard.writeText(text);

};

function showSuccess() { // Shows the green success text to the user.

    let success_text = document.getElementById("success-text");

    success_text.classList.remove("hidden");

};

function copyTextClass(ind) {

    let textElement = document.getElementsByClassName('text-to-copy-clipboard')[ind];

    let text = textElement.textContent;

    navigator.clipboard.writeText(text);

}
