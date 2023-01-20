import asyncio
import json
import requests

from okta_jwt_verifier import AccessTokenVerifier, IDTokenVerifier

from main import openvpnManager
from user import User

loop = asyncio.get_event_loop()


def is_access_token_valid(token, issuer):
    jwt_verifier = AccessTokenVerifier(issuer=issuer)
    try:
        loop.run_until_complete(jwt_verifier.verify(token))
        return True
    except Exception:
        return False


def is_id_token_valid(token, issuer, client_id, nonce):
    jwt_verifier = IDTokenVerifier(issuer=issuer, client_id=client_id, audience=client_id)
    try:
        loop.run_until_complete(jwt_verifier.verify(token, nonce=nonce))
        return True
    except Exception:
        return False


def load_config(fname='./client_secrets.json'):
    config = None
    with open(fname) as f:
        config = json.load(f)
    return config


config = load_config()


def process_access_token(access_token, state):
    # Authorization flow successful, get userinfo and login user
    userinfo_response = requests.get(config["userinfo_uri"],
                                     headers={'Authorization': f'Bearer {access_token}'})
    if userinfo_response.status_code != 200:
        return False
    userinfo_response = userinfo_response.json()
    unique_id = userinfo_response["sub"]
    user_email = userinfo_response["email"]
    user_name = userinfo_response["preferred_username"]
    username = userinfo_response["preferred_username"]
    print(userinfo_response)
    user = User(
        id_=unique_id, name=user_name, email=user_email
    )
    if not User.get(unique_id):
        User.create(unique_id, user_name, user_email)
    if openvpnManager.AllowUser(state, username):
        return user
    else:
        return False
