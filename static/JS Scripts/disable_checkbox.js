// Does exactly what it says - as soon as the user changes night/day mode - the checkbox immediately stops responding.
// This is done in order to prevent the user from querying the database 10 million times, stinkies :(

document.addEventListener('DOMContentLoaded', function() {

    let checkbox_element = document.getElementsByClassName("mode-input")[0];

    checkbox_element.addEventListener("click", function() {

        checkbox_element.disabled = true;

})
});
