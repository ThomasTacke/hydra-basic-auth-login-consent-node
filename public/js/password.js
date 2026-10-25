// Eye button in the password field: shows or hides the password
document.querySelectorAll("button.reveal").forEach(function (button) {
  var input = document.getElementById(button.getAttribute("aria-controls"))
  if (!input) return

  function setVisible(visible) {
    input.type = visible ? "text" : "password"
    button.setAttribute("aria-pressed", String(visible))
    button.setAttribute("aria-label", visible ? "Hide password" : "Show password")
  }

  button.hidden = false
  button.addEventListener("click", function () {
    setVisible(input.type === "password")
    input.focus()
  })
  // Submit as a password field, so password managers still offer to save it
  if (input.form) {
    input.form.addEventListener("submit", function () {
      setVisible(false)
    })
  }
})
