var socket = io();

var input = document.getElementById("domain-field");

document.getElementById("submit").addEventListener("click", (e) => {
  progress.innerHTML = "<h2>Progress</h2>";
  results.innerHTML = "<h2>Results</h2><p>Waiting for results</p>";
  socket.emit("find-subdomains", { domain: input.value });
});

var progress = document.getElementById("progress");
var results = document.getElementById("results");

socket.on("find-subdomains_progress", (message) => {
  progress.innerHTML += message + "<br/>"
});

socket.on("find-subdomains_error", (message) => {
  progress.innerHTML += message + "<br/>"
});

var subdomainsToSave = [];

socket.on("find-subdomains_result", (subdomains) => {
  subdomainsToSave = subdomains;
  results.innerHTML = "<h2>Results (" + subdomains.length + ")<button id=\"save\">Save</button></h2>";
  for (var i = 0; i < subdomains.length; i++) {
    results.innerHTML += subdomains[i] + "<br/>";
  }
});
