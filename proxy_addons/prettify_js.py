import jsbeautifier
from mitmproxy import ctx

class JSPrettifier:
    def __init__(self):
        self.opts = jsbeautifier.default_options()
        self.opts.indent_size = 2

    def response(self, flow):
        if flow.request.path.split("?")[0].split(".")[-1] == "js":
            result = jsbeautifier.beautify(flow.response.content.decode("utf8"), self.opts)
            result = bytes(result, "utf8")
            flow.response.content = result
            print("Matched, updating content to '" + result.decode("utf8") + "'")
        else:
            print("Doesn't match")

addons = [JSPrettifier()]
