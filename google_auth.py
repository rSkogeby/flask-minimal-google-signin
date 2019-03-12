#!/usr/bin/env python3
""" """

import os
import string
import random
import httplib2
import requests

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
    if request.args.get('state') != login_session['state']:
        return 'Fail'
    flow = flow_from_clientsecrets('instance/client_secrets',
                                scope='https://www.googleapis.com/auth/userinfo.email',
                                redirect_uri=client_secrets.get('redirect_uris')[0])
                                #access_type='offline', # Return both access and refresh token
                                #state=passthrough_value, # Provide a client Nonce
                                #include_granted_scopes='true') # Allow incremental authorization
    # Redirect the user to auth_uri on your platform.
    auth_uri = flow.step1_get_authorize_url()
    #login_session['flow'] = flow
    return redirect(auth_uri)


@app.route('/login/authorized')
def callback():
    code = request.args.get('code')
    session_state = request.args.get('session_state')
    scope = request.args.get('scope')
    authuser = request.args.get('authuser')
    prompt = request.args.get('prompt')

    # Pass code provided by authorization server redirection to this function
    flow = flow_from_clientsecrets('instance/client_secrets',
                                scope='https://www.googleapis.com/auth/userinfo.email',
                                redirect_uri=client_secrets.get('redirect_uris')[0])
    credentials = flow.step2_exchange(code)
    # Fetch some info
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}'.\
        format(access_token))
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    gplus_id = credentials.id_token['sub']
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    # Store the access token in session for later use
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
    login_session['provider'] = 'google'
    login_session['username'] = data['email']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    return 'Code: {}, credentials: {}, result: {}, email: {}'.format(code, credentials, result, login_session['username'])

    # Listen for response from authorization server
    #h = httplib2.Http('.cache')
    #resp, content = h.request(auth_uri, 'GET')
    #result = json.loads(resp)


    #return "Index, auth_uri: {}, state: {}, code: {}".format(auth_uri, login_session['state'], code.decode())

    

def main():
    app.secret_key = 'a_very_secret_key'
    app.run(host='localhost', port=8080, debug=True)


if __name__ == "__main__":
    main()
