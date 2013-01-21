#!/usr/bin/env python
# -*- coding: utf-8 -*- 

###############################################################################
## This is trimmed-down oauth implementation. 
##
## version 1.0
##               Initial implementation of oauth, oauth10 (oauth 1.0)  
##               and oauth20 (oauth 2.0)
## doc
##      oauth 1.0 specifications - http://tools.ietf.org/html/rfc5849
###############################################################################  

# standard imports
import base64
import hmac
import hashlib
import logging
import random
import time
import urllib

#define some constants
HTTP_METHOD = 'GET'

CONSUMER_KEY = ''
CONSUMER_SECRET = ''

# set these for own app tokens
TOKEN = ''
TOKEN_SECRET = ''

#set logger
logger = logging.getLogger(__name__)

class OAuthBase(object):
    
    #write common code between oauth 1 and oauth 2 here
    def __init__(self, consumer_key, consumer_secret):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
    
class OAuth10(OAuthBase):
    """
    use this class for OAuth 1.0 and XAuth, diff being for XAuth,
    we use token_secret only to sign request and consumer key/secret are annonymouse
    """
    def __init__(self, consumer_key, consumer_secret):
        self.oauth_version = '1.0'
        super(OAuth10, self).__init__(consumer_key=consumer_key, consumer_secret=consumer_secret)

    def url_quote(self, text):
        """
        quotes text to be url safe, wrapper over urllib.quote
        As per oauth standard "http://tools.ietf.org/html/rfc5849"
            Characters in the unreserved character set as defined by
            [RFC3986], Section 2.3 (ALPHA, DIGIT, "-", ".", "_", "~") MUST
            NOT be encoded.
        params
            text - text to be escaped
        returns
            escaped text
        """
        try:
            quoted_text = urllib.quote(text, safe='~-._')
        except Exception as e:
            quoted_text = None
            logger.error('oauth10.url_quote - %s' %e)

        return quoted_text

    def get_request_base_string(self, elements):
        """
        http://tools.ietf.org/html/rfc5849#section-3.4.1
        The signature base string is constructed by concatenating together,
           in order, the following HTTP request elements:

           1.  The HTTP request method in uppercase.  For example: "HEAD",
               "GET", "POST", etc.  If the request uses a custom HTTP method, it
               MUST be encoded (Section 3.6).

           2.  An "&" character (ASCII code 38).

           3.  The base string URI from Section 3.4.1.2, after being encoded
               (Section 3.6).

           4.  An "&" character (ASCII code 38).

           5.  The request parameters as normalized in Section 3.4.1.3.2, after
               being encoded (Section 3.6).
            
        """
        return '&'.join([self.url_quote(x) for x in elements])
        
    def generate_encoded_signature(self, base_str, token_secret):
        """
        creates a composite signing key of consumer secret and token secret if available
        e.g. for requesting token, token secret won't be available
        uses the composite signing key to create an oauth_signature from the signature base 
        signing method same as specified in common oauth params
        
        oauth_params['oauth_signature_method'] = 'HMAC-SHA1'
        """
        hmac_key = '&'.join([self.url_quote(self.consumer_secret), self.url_quote(token_secret)])
        return base64.b64encode((hmac.new(hmac_key, base_str, hashlib.sha1)).digest())

    def get_common_oauth_params(self):
        """
        gets parameters that are common to all oauth requests.
        """
        oauth_params = {}
        oauth_params['oauth_consumer_key'] = self.consumer_key 
        oauth_params['oauth_nonce'] = str(random.randrange(2**64 - 1))
        oauth_params['oauth_signature_method'] = 'HMAC-SHA1'
        oauth_params['oauth_version'] = self.oauth_version
        oauth_params['oauth_timestamp'] = str(int(time.time()))
        
        return oauth_params

    def generate_oauth_string(self, method=HTTP_METHOD, apiurl='', oauth_params=None, remove_secret=True, query_params={}):
        """
        Generates an OAUTH 1.0 authentication base string. This string will be signed later to form signed request
        params:
            method: GET/POST
            apiurl: request url
            oauth_params: dict containing oauth params
            remove_secret: indicating whether to remove oauth_token_secret from oauth_params. 
                            Generally for requests secret is used only for signing
                            and not in generating oauth string
            query_params: dict containing params to be passed as query string
                          ,used only for generating base string and signature, not used for final Oauth string
        """
        if not apiurl or apiurl.strip() == '':
            return
        
        pre_encoded_string = None
        
        if not oauth_params:
            oauth_params = self.get_common_oauth_params()
        
        try:
            oauth_token_secret = oauth_params['oauth_token_secret']
        except:
            oauth_token_secret = ''
        
        if remove_secret:
            try:
                del oauth_params['oauth_token_secret']
            except KeyError:
                pass
        
        try:
            oauth_params.update(query_params)
        except:
            pass

        try:
            #convert the parameter map into a URL query string
            #oauthparams to be sorted
            params = []
            for param in sorted(oauth_params.iteritems()):
                params.append('%s=%s' % (param[0], self.url_quote(param[1])))
            url_query_str = '&'.join(params)

            #get signature base string - http://tools.ietf.org/html/rfc5849#section-3.4.1
            oauth_base_string = self.get_request_base_string([method, apiurl, url_query_str])

            #generate auth signature
            encoded_signature = self.generate_encoded_signature(oauth_base_string, oauth_token_secret)
            
            oauth_params['oauth_signature'] = encoded_signature
            
            #remove query params, required only for generating base string
            try:
                for k in query_params.keys():
                    del oauth_params[k]
            except:
                pass
            
            #join the parameters using comma
            comma_joined_params = []
            for k, v in sorted(oauth_params.iteritems()):
                comma_joined_params.append('%s="%s"' % (k, self.url_quote(v)))
            param_list = ','.join(comma_joined_params)
            
            pre_encoded_string = param_list

        except Exception as e :
            logger.error('oauth10.generate_oauth_string - exception while generating oauth string %s' %e)
            pass
                
        return pre_encoded_string

class OAuth20(OAuthBase):
    """
    oauth 2.0 class
    """

    def __init__(self, consumer_key, consumer_secret):
        self.oauth_version = '2.0'
        super(OAuth20, self).__init__(consumer_key=consumer_key, consumer_secret=consumer_secret)

