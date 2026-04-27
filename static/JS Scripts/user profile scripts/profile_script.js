function previewFile() {
  let preview = document.querySelector('img');
  let file    = document.querySelector('input[type=file]').files[0];
  let reader  = new FileReader();

  reader.addEventListener("load", function () {
    preview.src = reader.result;
  });

  if (file) {
    // Detecting the file upload, and then showing both the image and the "Change profile picture" to the user.
    reader.readAsDataURL(file);
  }
}

document.addEventListener("DOMContentLoaded", function() {

    let pfp_prev = document.getElementById("profile-image1");
    let pfp_new = document.getElementById("profile-image-upload");
    let switcher = document.getElementsByClassName("mode-input")[0];

    if(document.body.classList.contains("dark")) { // Immediately flipping the switcher if body has a class "dark".

        switcher.checked = true;

    }

    pfp_prev.addEventListener('click', function() {

            pfp_new.click();

        });

    switcher.addEventListener("click", function() { // Redirects the user to the link, where the DB query

        window.location.replace("https://synovial-wilton-unspilt.ngrok-free.dev/toggle-theme");

    });
});
