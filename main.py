import requests

from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, render_template, redirect, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    logout_user, login_user,
)

from helpers import config, process_access_token
from openvpnssoman import OpenVPNSSOManager
from user import User


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

# Generate and place in client_secrets.json
# import secrets
# secrets.token_hex(24)
app.config.update({'SECRET_KEY': config["SECRET_KEY"]})
APP_STATE = 'ApplicationState'
NONCE = 'SampleNonce'

login_manager = LoginManager()
login_manager.init_app(app)

openvpnManager = OpenVPNSSOManager(config["management_port"], config["management_pw"], config["login_uri"])


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login")
def login():
    state = request.args.get("state")
    print(state)
    if not state:
        return "Unsupported login request", 403
    userStorage = openvpnManager.GetUser(state)
    print(userStorage)
    if not userStorage:
        return "Unsupported login request", 403
    # get request params
    query_params = {'client_id': config["client_id"],
                    'redirect_uri': config["redirect_uri"],
                    'scope': "openid email profile",
                    #'state': config["APP_STATE"],
                    'state': state,
                    'nonce': userStorage["nonce"],
                    'response_type': 'code',
                    'response_mode': 'query'}

    # build request_uri
    request_uri = "{base_url}?{query_params}".format(
        base_url=config["auth_uri"],
        query_params=requests.compat.urlencode(query_params)
    )

    return redirect(request_uri)


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)

@app.route("/success")
@login_required
def successfulLogin():
    return render_template("success.html", user=current_user)

@app.route("/authorization-code/callback")
def callback():
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    code = request.args.get("code")
    state = request.args.get("state")
    if not code:
        return "The code was not returned or is not accessible", 403
    print(state)
    if not state:
        return "The state was not returned or is not accessible", 403
    userStorage = openvpnManager.GetUser(state)
    print(userStorage)
    if not userStorage:
        return "Unknown login", 403
    query_params = {'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': config["redirect_uri"]
                    }
    print(request.base_url)
    query_params = requests.compat.urlencode(query_params)
    exchange = requests.post(
        config["token_uri"],
        headers=headers,
        data=query_params,
        auth=(config["client_id"], config["client_secret"]),
    ).json()

    # Get tokens and validate
    print(exchange)
    if not exchange.get("token_type"):
        return "Unsupported token type. Should be 'Bearer'.", 403

    access_token = exchange["access_token"]

    user = process_access_token(access_token, state)
    if user:
        login_user(user)

        return redirect(url_for("successfulLogin"))
    else:
        return "Unable to authenticate", 403


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


if __name__ == '__main__':
    print("Start manager")
    openvpnManager.Start()

    import bjoern
    bjoern.run(app, "127.0.0.1", 8080)
