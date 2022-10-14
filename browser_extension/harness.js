/* Constants */
const xssInjectionPayload = "aa<bbcc>dd";

/* Util */
const extractMatchingExcerpts = (text, searchString) => {
  var excerpts = [];
  while (true) {
    var position = text.search(searchString);
    if (position == -1) {
      break;
    }

    let max = text.length - 1;
    var excerptStart = Math.max(position - 10, 0);
    var excerptEnd = Math.min(position + 10 + searchString.length, max);
    var excerpt = text.slice(excerptStart, excerptEnd).trim();
    if (excerptStart != 0) {
      excerpt = "... " + excerpt;
    }
    if (excerptEnd != max) {
      excerpt += " ...";
    }

    excerpts.push(excerpt);

    text = text.replace(xssInjectionPayload, "_");
  }

  return excerpts;
}

/* Keyboard shortcuts */
const shortcuts = {
  "KeyP": () => {
    var input = document.activeElement;
    if (input["value"] !== undefined) {
      console.log("typing");
      input.value += xssInjectionPayload;
    } else {
      console.log("Not input");
    }
  },
  "KeyF": () => {
    console.log("Searching for successful XSS attempts...");

    var html = document.documentElement.outerHTML;

    var possibleXSSExcerpts = extractMatchingExcerpts(html, xssInjectionPayload);
    possibleXSSExcerpts.forEach((excerpt) => {
      console.info(`Found possible XSS!
  ${excerpt}`);
    });

    if (possibleXSSExcerpts.length == 0) {
      console.log("No successful injections found");
    }

    console.log("Search completed");
  }
}

document.addEventListener('keydown', (e) => {
  Object.entries(shortcuts).forEach(entry => {
    const [key, action] = entry;
    if (e.code === key && e.altKey && e.ctrlKey) {
      action();
    }
  });
});

/* Banner */
console.log(`
 __  __  ______  ____     __  __   ______   __  __  ____        __  __  ____    __       ____    ____    ____
/\\ \\/\\ \\/\\  _  \\/\\  _\`\\  /\\ \\/\\ \\ /\\__  _\\ /\\ \\/\\ \\/\\  _\`\\     /\\ \\/\\ \\/\\  _\`\\ /\\ \\     /\\  _\`\\ /\\  _\`\\ /\\  _\`\\
\\ \\ \\_\\ \\ \\ \\L\\ \\ \\ \\/\\_\\\\ \\ \\/'/'\\/_/\\ \\/ \\ \\ \`\\\\ \\ \\ \\L\\_\\   \\ \\ \\_\\ \\ \\ \\L\\_\\ \\ \\    \\ \\ \\L\\ \\ \\ \\L\\_\\ \\ \\L\\ \\
 \\ \\  _  \\ \\  __ \\ \\ \\/_/_\\ \\ , <    \\ \\ \\  \\ \\ , \` \\ \\ \\L_L    \\ \\  _  \\ \\  _\\L\\ \\ \\  __\\ \\ ,__/\\ \\  _\\L\\ \\ ,  /
  \\ \\ \\ \\ \\ \\ \\/\\ \\ \\ \\L\\ \\\\ \\ \\\\\`\\   \\_\\ \\__\\ \\ \\\`\\ \\ \\ \\/, \\   \\ \\ \\ \\ \\ \\ \\L\\ \\ \\ \\L\\ \\\\ \\ \\/  \\ \\ \\L\\ \\ \\ \\\\ \\
   \\ \\_\\ \\_\\ \\_\\ \\_\\ \\____/ \\ \\_\\ \\_\\ /\\_____\\\\ \\_\\ \\_\\ \\____/    \\ \\_\\ \\_\\ \\____/\\ \\____/ \\ \\_\\   \\ \\____/\\ \\_\\ \\_\\
    \\/_/\\/_/\\/_/\\/_/\\/___/   \\/_/\\/_/ \\/_____/ \\/_/\\/_/\\/___/      \\/_/\\/_/\\/___/  \\/___/   \\/_/    \\/___/  \\/_/\\/ /

Harness is installed. Hacking helper at your service...
`);
