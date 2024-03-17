// JavaScript for Sign Up Page

// Add event listeners for input fields and buttons
document.addEventListener("DOMContentLoaded", function () {
  let firstnameInput = document.querySelector(".firstname");
  let lastnameInput = document.querySelector(".lastname");
  let emailInput = document.querySelector(".email");
  let passwordInput = document.querySelector(".password");
  let cpasswordInput = document.querySelector(".cpassword");
  let signupButton = document.querySelector(".signup-button");

  // Add focus and blur event listeners for input fields
  firstnameInput.addEventListener("focus", handleInputFocus);
  firstnameInput.addEventListener("blur", handleInputBlur);
  lastnameInput.addEventListener("focus", handleInputFocus);
  lastnameInput.addEventListener("blur", handleInputBlur);
  emailInput.addEventListener("focus", handleInputFocus);
  emailInput.addEventListener("blur", handleInputBlur);

  // Function to handle input focus
  function handleInputFocus(event) {
    let length = Math.min(event.target.value.length - 16, 19);
    document.querySelectorAll(".hand").forEach((hand) => {
      hand.classList.remove("hide");
      hand.classList.remove("peek");
    });
    face.style.setProperty("--rotate-head", `${-length}deg`);
  }

  // Function to handle input blur
  function handleInputBlur(event) {
    face.style.setProperty("--rotate-head", "0deg");
  }

  // Add click event listener for sign-up button
  signupButton.addEventListener("click", handleSignUp);
});

// Function to handle sign-up button click
function handleSignUp(event) {
  // Add sign-up logic here
  alert("Sign Up button clicked!");
  
}
// JavaScript for Sign Up Page

// Add event listener for the Sign Up button
document.addEventListener("DOMContentLoaded", function () {
    let signupButton = document.querySelector(".signup-button");
  
    // Add click event listener for sign-up button
    signupButton.addEventListener("click", handleSignUp);
  });
  
  // Function to handle sign-up button click
  function handleSignUp(event) {
    // Hide icons when Sign Up button is clicked
    let icons = document.querySelectorAll(".fas");
    icons.forEach(function (icon) {
      icon.style.display = "none";
    });
  }
  showPasswordButton.addEventListener("click", (event) => {
  if (passwordInput.type === "text") {
    passwordInput.type = "password";
    document.querySelectorAll(".hand").forEach((hand) => {
      hand.classList.remove("peek");
      hand.classList.add("hide");
    });
  } else {
    passwordInput.type = "text";
    document.querySelectorAll(".hand").forEach((hand) => {
      hand.classList.remove("hide");
      hand.classList.add("peek");
    });
  }
});
