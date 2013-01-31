#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask, request, session, url_for, redirect, jsonify
from twoauth import TwitterOAuth10

app = Flask(__name__)
app.secret_key = '3\xf2h\xb7\xfc\xc4`\xf2\xa6\xd1\xbf\xd1R]e=8\x80\x8a\xf3fw\x16\x8b'

t = TwitterOAuth10('consumer_key', 'consumer_secret')

@app.route('/index')
def index():
    session = {}
    return "Hello, Flask"

@app.route('/oauth')
def oauth():
    if True:
        print url_for('oauth2', _external=True)
        request_token_data = t.get_request_token(url_for('oauth2', _external=True))
        # Store oauth_token_secret in session
        session['oauth_token_secret'] = request_token_data['oauth_token_secret']
        # Now redirect to the twitter API
        return redirect(request_token_data['api'])

@app.route('/oauth2')
def oauth2():
    print 'inside oauth2'
    print request.form
    print request.args
    if 'oauth_token' in request.args:
        user_data = t.get_access_token(request.args['oauth_token'],
                             request.args['oauth_verifier'],
                             session['oauth_token_secret'],
                             url_for('user_profile'))
        # Store the rest of the stuff in the session as well
        session['oauth_token'] = user_data['oauth_token']
        # token secret should be updated with new secret
        session['oauth_token_secret'] = user_data['oauth_token_secret']
        session['screen_name'] = user_data['screen_name']
        session['user_id'] = user_data['user_id']
    return redirect(url_for('user_profile'))

@app.route('/user_profile')
def user_profile():
    user_data = t.get_user_profile(oauth_token=session['oauth_token'], oauth_token_secret=session['oauth_token_secret'], twuser_id=session['user_id'])
    print user_data
    return jsonify(session)

if __name__ == '__main__':
    app.run(debug=True)
