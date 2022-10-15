import os

from recon.subdomain_finder import check_bruteforce, find_subdomains, default_services
from flask import Flask, render_template
from flask_socketio import SocketIO, emit

templates_dir = os.path.abspath("companion/templates")
app = Flask(__name__, template_folder=templates_dir)
app.config["SECRET_KEY"] = "i'm a security researcher so it's impossible to hack me"
socketio = SocketIO(app)

@app.route("/")
def index():
  return render_template("index.html")

@socketio.on("find-subdomains")
def find_subdomains_event(json):
  if not "domain" in json:
      emit("find-subdomains_error", "Missing 'domain' query parameter")
  domain = json["domain"]

  services = list(default_services)
  services.append(("bruteforce", check_bruteforce))

  def log(message: str):
    emit("find-subdomains_progress", message)

  try:
    subdomains = find_subdomains(domain, services, log)
  except KeyboardInterrupt:
    exit(1)
  except Exception as e:
    emit("find-subdomains_error", f"Subdomain finder encountered fatal error: {e}")
    return

  emit("find-subdomains_result", subdomains)

if __name__ == "__main__":
  socketio.run(app, host="localhost", port=1377)
