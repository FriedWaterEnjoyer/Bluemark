// The main purpose of this file is to preprocess the image that the user inserts on the upload-page.

// Then it prevents default behavior of the form, creates its own - then adds all the images, text and tags - and then sends it to the main server.

document.addEventListener('DOMContentLoaded', function() {

function checkSize(input) { // Checks if the size of the input is less than or equal to 2Mb. If not - returns false.
        if(input.target.files[0].size > 2000001) {

           return false;

        } else {

            return true;

        }
};

let uploadButton = document.getElementById('file');

let submitFormButton = document.getElementsByClassName("upload-submit")[0]

let count = 0; // Will be responsible for limiting the amount of images the user can upload.

let all_images = []; // What will be sent to the backend.


uploadButton.addEventListener('change', (e)=>{ // Activates when the user's trying to upload an image.

    // There are two conditions that must be satisfied:

    // 1 - The size of the image doesn't exceed 2Mb;

    // 2 - The user has uploaded no more than 5 images.

    // If at least one of those conditions isn't met - then the program sends an appropriate error message, telling the user what went wrong.

    document.getElementsByClassName("img-am-info")[0].classList.add("hidden");

    const currFiles = e.target.files;
    if(currFiles.length > 0 && checkSize(e) && count < 5){
          let src = URL.createObjectURL(currFiles[0]);
          let imagePreview = document.getElementById('file-preview');
          imagePreview.src = src;
          imagePreview.style.display = "block";
          document.getElementsByClassName("file-size-error")[0].classList.add("hidden");
          document.getElementsByClassName("icon")[0].classList.add("hidden");
          document.getElementsByClassName("text")[0].classList.add("hidden");
          document.getElementsByClassName("image-success")[0].classList.remove("hidden");
          document.getElementById("file-preview").classList.remove("hidden");

          const img_selected = Array.from(e.target.files); // Getting the uploaded file if it passes the preprocessing part.

          all_images.push(...img_selected);

          count++;

    } else if(!(checkSize(e))) { // If the size requirement isn't met.

        document.getElementsByClassName("image-success")[0].classList.add("hidden");
        document.getElementsByClassName("file-size-error")[0].classList.remove("hidden");
        uploadButton.value = "";

    } else { // If the user's reached maximum amount of image uploads.

        document.getElementsByClassName("image-success")[0].classList.add("hidden");
        document.getElementsByClassName("file-size-error")[0].classList.add("hidden");
        document.getElementsByClassName("max-img-am")[0].classList.remove("hidden");
        // uploadButton.value = "";

    }
    })

// Manually processing the entire form because I need to send a list of images, not just a single image.

document.getElementsByClassName("main-upload-form")[0].addEventListener("submit", async (e) => {

        submitFormButton.disabled = true; // Disabling the form submission, since the loading kicks in a few seconds after the user's pressed the submit button.

        e.preventDefault();

        const form = e.target;

        const formData = new FormData(); // Creating a new data.


        // Copying all the form fields besides the images:

        for (let element of form.elements) {

            if (element.name && element.type === "file") continue;

            if (element.tagName === "SELECT" && element.multiple) {

                Array.from(element.selectedOptions).forEach(opt => {

                    formData.append(element.name, opt.value);

                });

                continue;

            }

            formData.append(element.name, element.value);

        }

        // Taking care of the images:


        all_images.forEach((file) => {

            formData.append("product_img", file);

        })

        // Submitting the form itself.

        const response = await fetch("/upload", {

            method: "POST",
            body: formData,

        })

        const result = await response.json();

        // Go to the redirect.


        if (result.redirect) {

            window.location.href = result.redirect;

        }

    })

})
