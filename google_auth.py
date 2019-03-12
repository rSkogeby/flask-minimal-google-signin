#!/usr/bin/env python3
""" """

import os
import string
import random
import httplib2

from flask import Flask, jsonify, request, render_template, url_for, redirect
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from OpenSSL import SSL
import json

client_secrets_file = open('instance/client_secrets').read()
client_secrets = json.loads(client_secrets_file).get('web')


app = Flask(__name__)

@app.route('/')
@app.route('/login/')
def login():
    template_args = {}
    passthrough_value = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = passthrough_value
    template_args['state'] = login_session['state']

    return render_template('login.html', args=template_args)
    
@app.route('/login/gconnect', methods=['GET', 'POST'])
def gconnect():
    flow = flow_from_clientsecrets('instance/client_secrets',
                                scope='openid',
                                redirect_uri=client_secrets.get('redirect_uris')[0])
                                #access_type='offline', # Return both access and refresh token
                                #state=passthrough_value, # Provide a client Nonce
                                #include_granted_scopes='true') # Allow incremental authorization
    # Redirect the user to auth_uri on your platform.
    auth_uri = flow.step1_get_authorize_url()
    return redirect(auth_uri)


@app.route('/login/authorized')
def callback():
    return "Callback"

    # Pass code provided by authorization server redirection to this function
    #credentials = flow.step2_exchange(code)

    # Listen for response from authorization server
    #h = httplib2.Http('.cache')
    #resp, content = h.request(auth_uri, 'GET')
    #result = json.loads(resp)
    #code = request.data


    #return "Index, auth_uri: {}, state: {}, code: {}".format(auth_uri, login_session['state'], code.decode())

    

def main():
    app.secret_key = 'a_very_secret_key'
    app.run(host='localhost', port=8080, debug=True)


if __name__ == "__main__":
    main()
