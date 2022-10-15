var target = document.getElementById("target");
var frame = document.getElementById("frame");

frame.addEventListener("error", (e) => {
  target.innerHTML = "";
  target.textContent = "ERROR: Failed to load companion, are you sure that it's running?";
})
