document.onreadystatechange = function () {
  console.log("change");
  if (document.readyState == "interactive") {
    console.log("load");
    var target = document.getElementById("target");
    var frame = document.getElementById("frame");

    console.log("requesting site");
    fetch(frame.src)
      .catch(() => {
        target.innerHTML = `ERROR: Failed to load companion, are you sure that it's running?
<style>#target { padding: 2em; box-sizing: border-box; }</style>`;
      });
  }
};
