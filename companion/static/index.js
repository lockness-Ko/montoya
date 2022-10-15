var socket = io();

/* Form handler */

var input = document.getElementById("domain-field");
var domain = "";
var button = document.getElementById("submit");
button.addEventListener("click", (e) => {
  progress.innerHTML = "<h2>Progress</h2>";
  results.innerHTML = "<h2>Results</h2> Waiting for results";
  domain = input.value;
  socket.emit("find-subdomains", { domain: domain });
});

input.addEventListener("keydown", (e) => {
  if (e.key == "Enter") {
    button.click();
    input.blur();
  }
})

/* Autofill input */

function urlParam(name) {
  var results = new RegExp("[?&]" + name + "=([^&#]*)").exec(
    window.location.search
  );
  return results !== null ? results[1] || 0 : false;
}

var param = urlParam("domain");
if (param !== false) {
  input.value = param;
}

/* Dynamic elements */

var progress = document.getElementById("progress");
var results = document.getElementById("results");

/* Socket listeners */

socket.on("find-subdomains_progress", (message) => {
  progress.innerHTML += message + "<br/>";
});

socket.on("find-subdomains_error", (message) => {
  progress.innerHTML += message + "<br/>";
});

socket.on("find-subdomains_result", (subdomains) => {
  dataURI = "data:text/plain;base64," + window.btoa(subdomains.join("\n"));
  results.innerHTML =
    "<h2>Results (" +
    subdomains.length +
    ') <a href="' +
    dataURI +
    '" download="' +
    domain +
    '.txt" id="save" class="button">Save</button></a>';
  for (var i = 0; i < subdomains.length; i++) {
    results.innerHTML += subdomains[i] + "<br/>";
  }
});
