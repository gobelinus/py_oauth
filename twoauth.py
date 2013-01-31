#!/usr/bin/env python
# -*- coding: utf-8 -*-

###############################################################################
##
## doc
##      oauth 1.0 specifications - http://tools.ietf.org/html/rfc5849
##      twitter - https://dev.twitter.com/docs/auth/oauth
## https://dev.twitter.com/docs/auth/implementing-sign-twitter
###############################################################################

# standard imports
import urllib
import logging

# external libraries
import httplib2

#local modules
import oauth

#define some constants
REQUEST_BASE_URL = 'https://api.twitter.com'
REQUEST_TOKEN_URL = 'https://api.twitter.com/oauth/request_token'
ACCESS_TOKEN_URL = 'https://api.twitter.com/oauth/access_token'
HOME_TIMELINE_URL = 'https://api.twitter.com/1.1/statuses/home_timeline.json'
POST_STATUS_URL = 'https://api.twitter.com/1.1/statuses/update.json'
VERIFY_URL = 'http://api.twitter.com/1.1/account/verify_credentials.json'

USER_PROFILE_URL = 'https://api.twitter.com/1.1/users/show.json'
USER_TIMELINE_URL = 'https://api.twitter.com/1.1/statuses/user_timeline.json'
AUTHENTICATE_URL = 'https://api.twitter.com/oauth/authenticate?oauth_token=%(token)s'


#set logger
logger = logging.getLogger(__name__)

class TwitterOAuth10(oauth.OAuth10):

    def __init__(self, consumer_key, consumer_secret):
        #host is required, we will genereate key/secret from method above
        super(TwitterOAuth10, self).__init__(consumer_key=consumer_key, consumer_secret=consumer_secret)

    def get_header(self, method=oauth.HTTP_METHOD, apiurl ='', oauth_params=None, query_params={}):

        oauth_string = self.generate_oauth_string(method=method
                                                  ,apiurl=apiurl
                                                  ,oauth_params=oauth_params
                                                  ,query_params=query_params)
        auth_header = 'OAuth %s' %oauth_string
        return {'Authorization': auth_header}

    def request_twitter(self, api='', method=oauth.HTTP_METHOD, oauth_header=None, params=None):
        """
        Requests twitter with a url and fetches results.
        Doc - https://dev.twitter.com/docs/auth/oauth

        Arguments:
            api - url to be fetched
            method - type of request GET/PUT/POST/DELETE
            oauth_header - oauth Authorization header after signing properly
            params - request params to be passed to twitter as request body
        Returns:
            response - Request response inlcudes status, content length etc etc
            content - Request content e.g. tweets in XML format for tweets request
        """

        if not api or api.strip() == '':
            return None

        request_headers = None
        if oauth_header:
            request_headers = oauth_header

        qs = None
        if params and len(params) > 0 and isinstance(params, dict):
            qs = urllib.urlencode(params)

        if qs:
            api = api +'?' + qs

        response, content = ['', '']
        #httplib2.debuglevel = 10
        response, content = httplib2.Http().request(api, method=method, headers=request_headers)
        #print response
        #print content
        return (response, content)

    def get_request_token(self, callback):
        """
        get request token from twitter
        https://dev.twitter.com/docs/auth/implementing-sign-twitter
        redirect to 'api' returned in return values, prior to redirection
        save oauth token secret
        """
        method = 'POST'
        apiurl = REQUEST_TOKEN_URL

        #for local testing use oob as twitter treats localhost urls like a desktop application
        #oauth_callback = 'oob'
        oauth_params = self.get_common_oauth_params()
        oauth_params['oauth_callback'] = callback

        oauth_header = self.get_header(method, apiurl, oauth_params)

        response = None
        content = None
        response, content = self.request_twitter(apiurl, method, oauth_header)

        if content and content.strip() != '':
            #separate the token and token secrets
            #response is something like oauth_token=x...Ow&oauth_token_secret=my..Kgs&oauth_callback_confirmed=true
            try:
                request_token = dict(info.split('=') for info in content.split('&'))
            except:
                return None

            #exchange this token for authorization
            #https://dev.twitter.com/docs/auth/implementing-sign-twitter
            # redirect to this api, prior to this api, save auth token secret,
            api = AUTHENTICATE_URL %dict(token=request_token['oauth_token'])
            request_token['api'] = api
            return request_token

        return

    def get_access_token(self, oauth_token, oauth_verifier, oauth_token_secret, oauth_callback):
        """
        get access token for a user
        """
        method = 'POST'
        apiurl = ACCESS_TOKEN_URL

        #for local testing use oob as twitter treats localhost urls like a desktop application
        #oauth_callback = 'oob'
        oauth_params = self.get_common_oauth_params()
        oauth_params['oauth_callback'] = oauth_callback
        oauth_params['oauth_token'] = oauth_token
        oauth_params['oauth_verifier'] = oauth_verifier
        oauth_params['oauth_token_secret'] = oauth_token_secret


        oauth_header = self.get_header(method, apiurl, oauth_params)
        response, content = self.request_twitter(apiurl, method, oauth_header)
        if content and content.strip() != '':
            #separate the token and token secrets
            try:
                access_token = dict(info.split('=') for info in content.split('&'))
            except:
                return None

            return access_token

        return None

    def get_home_timeline(self, oauth_token, oauth_token_secret, last_tweet=''):
        """
        gets users home timeline to fetch tweets
        """
        method='GET'

        oauth_params = self.get_common_oauth_params()
        oauth_params['oauth_token'] = oauth_token
        oauth_params['oauth_token_secret'] = oauth_token_secret


        apiurl = HOME_TIMELINE_URL
        query_params = {'include_entities' : 'true', 'count': '100'}
        # if we have last tweet id, then use it else fetch latest 20 tweets (can be increased later)
        if last_tweet and str(last_tweet).strip() != '':
            query_params['since_id'] = str(last_tweet).strip()

        oauth_header = self.get_header(method, apiurl, oauth_params, query_params=query_params)
        response, content = ['', '']
        response, content = self.request_twitter(apiurl, method, oauth_header, query_params)
        return content

    def update_status(self, status, oauth_token, oauth_token_secret):
        """
        Post a tweet

        Remixes code from get_home_timeline
        Twitter doc: https://dev.twitter.com/docs/api/1.1/post/statuses/update
        """

        method = 'POST'
        oauth_params = self.get_common_oauth_params()
        oauth_params['oauth_token'] = oauth_token
        oauth_params['oauth_token_secret'] = oauth_token_secret

        query_params = {'status' : status, 'trim_user' : 'true', 'include_entities' : 'true'}
        oauth_header = self.get_header(method, POST_STATUS_URL, oauth_params, query_params=query_params)
        response, content = ['', '']
        response, content = self.request_twitter(POST_STATUS_URL, method, oauth_header, query_params)
        return content

    def get_user_profile(self, oauth_token, oauth_token_secret, twuser_id):
        """
        fetches user profile from twitter
        Doc: https://dev.twitter.com/docs/api/1.1/get/users/show
        """
        if not twuser_id:
            return
        query_params = {'user_id': twuser_id}
        method='GET'
        #print oauth_token, oauth_token_secret
        oauth_params = self.get_common_oauth_params()
        oauth_params['oauth_token'] = oauth_token
        oauth_params['oauth_token_secret'] = oauth_token_secret
        apiurl = USER_PROFILE_URL
        oauth_header = self.get_header(method, apiurl, oauth_params, query_params=query_params)
        response, content = ['', '']
        response, content = self.request_twitter(apiurl, method, oauth_header, query_params)
        #print content
        return content

    def get_user_timeline(self, oauth_token, oauth_token_secret, last_tweet=''):
        """
        gets user timeline to fetch tweets
        doc - https://dev.twitter.com/docs/api/1.1/get/statuses/user_timeline
        """
        method='GET'
        #print oauth_token, oauth_token_secret
        oauth_params = self.get_common_oauth_params()
        oauth_params['oauth_token'] = oauth_token
        oauth_params['oauth_token_secret'] = oauth_token_secret

        apiurl = USER_TIMELINE_URL
        query_params = {'include_entities' : 'true', 'count': '100', 'exclude_replies': 'false', 'include_rts': 'true'}
        if last_tweet and str(last_tweet).strip() != '':
            query_params['since_id'] = str(last_tweet).strip()

        oauth_header = self.get_header(method, apiurl, oauth_params, query_params=query_params)
        response, content = ['', '']
        response, content = self.request_twitter(apiurl, method, oauth_header, query_params)
        return content

