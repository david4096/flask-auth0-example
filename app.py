# Hi there! Today, we're going to make a simple flask app that is secured using auth0.

# First we'll set up a basic flask app.
import flask
import flask.ext.cors as cors
app = flask.Flask(__name__)

# We also want the request module for retrieving authorization tokens. And jwt, json, and
# base64 for help parsing them. Urllib helps us make URL encoded query strings.
import requests
import jwt
import base64
import json
import urllib

# There are some things we don't want to hard code that we'll get from the environment.
# These are constants that allows us to identify our application to auth0. We use a 
# convencience library for setting the defaults and accepting these configuration values
# from the environment.
from flask_environ import get, collect, word_for_true

app.config.update(collect(
    get('DEBUG', default=True, convert=word_for_true),
    get('HOST', default='localhost'),
    get('PORT', default=5000, convert=int),
    get('CLIENT_ID', default="7PyT5eQRRdaSxgM4hEYz04wzncNiXpqH"),
    get('CLIENT_SECRET', default="2OkzpU7LMYMllXf7cd027WFcbBpb4b_p3iNRaUfsYOQgxiYM_puwRxCddCRy_RtV"),
    get('AUTH_HOST', default='david4096.auth0.com'),
    get('SCOPE', default='openid email'),
    get('SECRET_KEY', default="abc")))

# This will be the callback URL Auth0 returns the authenticatee to.
app.config['CALLBACK_URL'] = 'http://{}:{}/callback'.format(app.config.get('HOST'), app.config.get('PORT'))

# When we protect a path, we'll add a simple function decorator. For that we need functools
import functools

# To store the current login states, we'll use a simple cache
from werkzeug.contrib.cache import SimpleCache
cache = SimpleCache()

# We'll have a landing page so that people can log in.
# This decorator tells flask to serve this function from `/`
@app.route("/")
def hello():
  # If an API key has been requested via the callback, we'll display it
  code = flask.request.args.get('code') 
  if code:
    return flask.render_template('key.html', app=app, key=code, session=flask.session)
  # Otherwise we need to render a login screen. Auth0 hosts a script that
  # we can drop in.
  else:
    return flask.render_template('login.html', app=app)


# In order to make it so an endpoint is protected we need to do a couple of things.
# The first is a little helper function that will kick back authorization failures
# with hopefully helpful error codes.
def authenticate(error):
  resp = flask.jsonify(error)
  resp.status_code = 401
  return resp

# Next we need to expose an endpoint so that auth0 can provide a signed token when
# someone has authenticated themselves. This will redirect the login process to a 
# page where someone might collect their API key. Since it posts data to Auth0
# we need to import the requests module.
@app.route('/callback')
def callback_handling():
  code = flask.request.args.get('code')
  json_header = {'content-type': 'application/json'}
  token_url = "https://{domain}/oauth/token".format(domain='david4096.auth0.com')
  token_payload = {
    'client_id':     app.config.get('CLIENT_ID'),
    'client_secret': app.config.get('CLIENT_SECRET'),
    'redirect_uri':  'http://{}:{}/{}'.format(app.config.get('HOST'), app.config.get('PORT'), app.config.get('CALLBACK_URL')),
    'code':          code,
    'grant_type':    'authorization_code'
  }
  token_info = requests.post(token_url, data=json.dumps(token_payload), headers = json_header).json()
  # TODO failures against auth0 should be properly handled here
  user_url = "https://{domain}/userinfo?access_token={access_token}" \
      .format(domain=app.config.get('AUTH_HOST'), access_token=token_info['access_token'])
  user_info = requests.get(user_url).json()
  
  # We're saving all user information into the app.
  # Practically speaking, these should be placed in a database.
  cache.set(token_info['id_token'], user_info)
  
  # A nice cognitive optimization might be to give back fewer characters of the token
  # and then use the session to look up the full token in `requires_auth`. This may limit
  # the ways you can distribute API tokens.

  # Redirect to the User logged in page that you want here
  # In our case it's /dashboard
  return flask.redirect('/?code={}'.format(token_info['id_token']))


# This decorator wraps any function that needs to have an authorized header to be
# served from. It just checks to see if the key that is being used is still good.
def requires_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth = flask.request.headers.get('Authorization', None)
        if not auth:
          return authenticate({'code': 'authorization_header_missing', 'description': 'Authorization header is expected'})
        print(auth)
        parts = auth.split()

        if parts[0].lower() != 'bearer':
          print("bad bearer")
          return authenticate({'code': 'invalid_header', 'description': 'Authorization header must start with Bearer'})
        elif len(parts) == 1:
          print("bad token")
          return authenticate({'code': 'invalid_header', 'description': 'Token not found'})
        elif len(parts) > 2:
          print("too much info")
          return authenticate({'code': 'invalid_header', 'description': 'Authorization header must be Bearer + \s + token'})

        token = parts[1]
        try:
            payload = jwt.decode(
                token,
                base64.b64decode(app.config.get('CLIENT_SECRET').replace("_","/").replace("-","+")),
                audience=app.config.get('CLIENT_ID'))
        except jwt.ExpiredSignature:
            return authenticate({'code': 'token_expired', 'description': 'token is expired'})
        except jwt.InvalidAudienceError:
            return authenticate({'code': 'invalid_audience', 'description': 'incorrect audience, expected: k6QtEc3VDboQKEtgFLYgEM9G9YhVMV86'})
        except jwt.DecodeError:
            return authenticate({'code': 'token_invalid_signature', 'description': 'token signature is invalid'})
        flask.session['key'] = token
        flask._request_ctx_stack.top.current_user = user = payload
        return f(*args, **kwargs)
    return decorated

# Now that we have a way of protecting an endpoint, let's create an endpoint and add the decorator.
@app.route("/protected")
@requires_auth
@cors.cross_origin(headers=['Content-Type', 'Authorization'])
def protected():
  # A well issued token will not reach this point, however, logins need to be managed by
  # your application.
  if cache.get(flask.session['key']):
    return flask.jsonify(cache.get(flask.session['key']))
  else:
    response = flask.jsonify({'message': 'Good token, bad session'})
    response.status_code = 401
    return response

# Lastly, we'll provide an endpoint for logging out. 
@app.route("/logout")
@requires_auth
@cors.cross_origin(headers=['Content-Type', 'Authorization'])
def logout():
  key = flask.session.get('key')
  flask.session.clear()
  cache.set(key, None)
  return flask.redirect('https://{}/v2/logout?access_token={}&?client_id={}'.format(app.config.get('AUTH_HOST'), key, app.config.get('CLIENT_ID'), "http://{}:{}/".format(app.config.get('HOST'), app.config.get('PORT'))))

if __name__ == "__main__":
  app.run(host=app.config.get('HOST'), port=app.config.get('PORT'))