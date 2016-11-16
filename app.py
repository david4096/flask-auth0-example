import flask
import flask.ext.cors as cors
app = flask.Flask(__name__)

# This module simply makes it easier to collect environment variables
from flask_environ import get, collect, word_for_true

app.config.update(collect(
    get('DEBUG', default=True, convert=word_for_true),
    get('HOST', default='localhost'),
    get('PORT', default=5000, convert=int),
    get('CLIENT_ID', default="7PyT5eQRRdaSxgM4hEYz04wzncNiXpqH"),
    get('CLIENT_SECRET', default="2OkzpU7LMYMllXf7cd027WFcbBpb4b_p3iNRaUfsYOQgxiYM_puwRxCddCRy_RtV"),
    get('AUTH_HOST', default='david4096.auth0.com'),
    get('SCOPES', default='openid email'),
    get('SECRET_KEY', default="abc"),
    get('USERS', default="davidcs@ucsc.edu,rcurrie@ucsc.edu,broconno@ucsc.edu")))

# This will be the callback URL Auth0 returns the authenticatee to. When Auth0 returns someone
# to this URL, we have to perform a few actions, but then we can redirect them to a page of
# our choosing. Our app serves a simple key viewer page at the main screen.
app.config['CALLBACK_URL'] = 'http://{}:{}/callback'.format(app.config.get('HOST'), app.config.get('PORT'))

# Now we'll import our auth module, which provides authorization and authentication. We do this
# by creating a decorator with our Auth0 client configuration.
# `authorized` is a list of emails that we expect to see returned in Auth0 user profiles.
import auth
requires_auth = auth.auth_decorator(client_id=app.config.get('CLIENT_ID'),
                                    client_secret=app.config.get('CLIENT_SECRET'),
                                    authorized=app.config.get('USERS').split(','))

# We'll have a landing page so that people can log in.
@app.route("/")
def hello():
  # If an API key has been requested via the callback, we'll display it, this is what can
  # be used with cURL clients, etc, or the built in HTTP client in `key.html`.
  code = flask.request.args.get('code') 
  if code:
    return flask.render_template('key.html', app=app, key=code, session=flask.session)
  else:
    # Otherwise we return a simple login page (batteries included)
    return flask.redirect('/login')

@app.route("/login")
def login():
    return auth.render_login(
        app=app,
        scopes=app.config.get('SCOPES'),
        redirect_uri=app.config.get('CALLBACK_URL'),
        domain=app.config.get('AUTH_HOST'),
        client_id=app.config.get('CLIENT_ID'))

@app.route('/callback')
def callback_handling():
  redirect_uri = 'http://{}:{}/{}'.format(
      app.config.get('HOST'),
      app.config.get('PORT'),
      app.config.get('CALLBACK_URL'))
  return auth.callback_maker(
      domain=app.config.get('AUTH_HOST'),
      client_id=app.config.get('CLIENT_ID'),
      client_secret=app.config.get('CLIENT_SECRET'),
      redirect_uri=redirect_uri)()

@app.route("/protected")
@requires_auth
@cors.cross_origin(headers=['Content-Type', 'Authorization'])
def protected():
  # Only requests bearing tokens that have been shown to belong
  # to a member of the authorized list should reach this point.
  # The details of their profile is available in the cache via
  # mapped to their API key.
  return flask.jsonify(auth.cache.get(flask.session['key']))

# Lastly, we'll provide an endpoint for logging out. 
@app.route("/logout")
@requires_auth
@cors.cross_origin(headers=['Content-Type', 'Authorization'])
def logout():
  key = flask.session['key']
  auth.logout()
  return flask.redirect('https://{}/v2/logout?access_token={}&?client_id={}'.format(
      app.config.get('AUTH_HOST'),
      key,
      app.config.get('CLIENT_ID'),
      "http://{}:{}/".format(app.config.get('HOST'),
                             app.config.get('PORT'))))

if __name__ == "__main__":
  app.run(host=app.config.get('HOST'), port=app.config.get('PORT'))