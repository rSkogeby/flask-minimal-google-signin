#!/usr/bin/env python3
""" """

import os
import string
import random

from flask import Flask, jsonify, request
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from OpenSSL import SSL
import json

client_secrets_file = open('instance/client_secrets').read()
client_secrets = json.loads(client_secrets_file).get('web')


app = Flask(__name__)

@app.route('/')
def index():
    passthrough_value = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = passthrough_value
    flow = flow_from_clientsecrets('instance/client_secrets',
                                scope='',
                                redirect_uri=client_secrets.get('redirect_uris')[0])
                                #access_type='offline', # Return both access and refresh token
                                #state=passthrough_value, # Provide a client Nonce
                                #include_granted_scopes='true') # Allow incremental authorization

    # Redirect the user to auth_uri on your platform.
    auth_uri = flow.step1_get_authorize_url()

    # Listen for response from authorization server
    code = request.data

    # Pass code provided by authorization server redirection to this function
    #credentials = flow.step2_exchange(code)
    return "Index, auth_uri: {}, state: {}, code: {}".format(auth_uri, login_session['state'], code.decode())

@app.route('/login/authorized')
def callback():
    

def main():
    app.secret_key = 'a_very_secret_key'
    app.run(host='localhost', port=8080, debug=True)


if __name__ == "__main__":
    main()
