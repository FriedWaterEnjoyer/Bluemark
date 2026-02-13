document.addEventListener('DOMContentLoaded', function() {

    let valid_extensions = ["jpg", "jpeg", "png"];

    function checkExtension(filename) {

        const fileExtension = filename.name.split('.').pop().toLowerCase();
        return valid_extensions.includes(fileExtension);

    }

    let upload_button = document.getElementsByClassName("pfp-update-submit")[0]; // The "upload pfp" button.

    upload_button.disabled = true; // Will enable the button when the user sends a file.

    function checkSize(input) {

        if (input.target.files[0]) {

            if (!checkExtension(input.target.files[0])) {

                return "Incorrect file extension";

            };

            if(input.target.files[0].size > 1500001) { // Since the maximum size is 1.5 MB.

               return false;

            } else {

                return true;

            }

        } else {

            return "No file submitted";

        }
    };

    let img_submit_not = false; // Determines whether the user can send his selected pfp or not.

    let hint_txt = document.getElementsByClassName("pfp-hint")[0]; // A hint that tells the user what to do in order to change the pfp.

    let file_size = document.getElementsByClassName("file-size-message")[0]; // Text about the maximum size of the image.

    let error_message = document.getElementsByClassName("file-error")[0]; // For displaying the error message. (File size exceeded 1.5 Mb).

    let extension_error = document.getElementsByClassName("file-type-error")[0]; // For displaying the error message. (Incorrect file extension).

    let full_pfp_form = document.getElementsByClassName("user-pfp-form")[0];

    let img_preview = document.getElementById("profile-image-upload");


    full_pfp_form.addEventListener("change", function(e) {


        let file_check = checkSize(e);

        const currFiles = e.target.files;


        if(currFiles.length > 0 && file_check !== "No file submitted" && file_check !== "Incorrect file extension" && file_check) {

            error_message.classList.add("hidden");

            extension_error.classList.add("hidden");

            hint_txt.classList.remove("hidden");

            file_size.classList.remove("hidden");

            upload_button.disabled = false;

        } else if(file_check === "No file submitted") {

            upload_button.disabled = true;

        } else if(file_check === "Incorrect file extension") {

            upload_button.disabled = true;

            hint_txt.classList.add("hidden");

            file_size.classList.add("hidden");

            error_message.classList.add("hidden");

            extension_error.classList.remove("hidden");

        } else {

            upload_button.disabled = true;

            hint_txt.classList.add("hidden");

            file_size.classList.add("hidden");

            extension_error.classList.add("hidden");

            error_message.classList.remove("hidden");

        }


    });

});
