from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/")
def index():
  return render_template("index.html")

@app.route("/xssable")
def xssable():
  return "You entered '" + request.args["input"] + "'<br/><a href='/'>Go back</a>"

app.run("0.0.0.0", port=1337)
