window.onload = () => {
  var frame = document.getElementById("frame");

  /* Automatically fill in domain field if possible */
  browser.tabs.query({currentWindow: true, active: true})
    .then((tabs) => {
      var url = new URL(tabs[0].url);
      if (url.hostname !== "") {
        frame.src += "?domain=" + url.hostname;
      }
    });
};
