// Responsible for the carousel functionality.

// Querying all the necessary HTML elements.

const carousel = document.querySelector('.carousel');
const track = carousel.querySelector('.carousel__items');
const items = carousel.querySelectorAll('.carousel__item');
const nextBtn = carousel.querySelector('.next');
const prevBtn = carousel.querySelector('.prev');
const dots = carousel.querySelectorAll('.dot');


let index = 0; // Index of the image.
const total = items.length;

function updateCarousel() {

  track.style.transform = `translateX(-${index * 100}%)`;

  dots.forEach(dot => dot.classList.remove('active'));
  if (dots[index]) dots[index].classList.add('active');

}

nextBtn.addEventListener('click', () => {

  index = (index + 1) % total; // wrap-around for the right-side.
  updateCarousel();

});

prevBtn.addEventListener('click', () => {

  index = (index - 1 + total) % total; // wrap-around for the left-side.
  updateCarousel();

});

dots.forEach(dot => {

  dot.addEventListener('click', () => {
    index = parseInt(dot.dataset.index);
    updateCarousel();

  });
});


document.addEventListener("DOMContentLoaded", () => {

    updateCarousel();

})
