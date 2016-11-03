# flask-auth0-example
Provides a boilerplate for securing your API using Auth0. It uses jwt and provides a simple login using an in-memory cache.

## Usage

This is meant to provide a simple example of using Auth0 to secure an API.

It has very few requirements, listed in the `requirements.txt`. To install them use `pip install -r requirements.txt`.

`python app.py` will start an HTTP server at http://localhost:5000. Visit this page to log in.

## Using environment variables

To use you own Auth0 account you must provide a Client ID, Client Secret, and the host used to authenticate against. This can be done by providing environment variables when running the server.

    
    CLIENT_ID=7PyT5eQRRdaSxgM4hEYz04wzncNiXpqH \
    CLIENT_SECRET=2OkzpU7LMYMllXf7cd027WFcbBpb4b_p3iNRaUfsYOQgxiYM_puwRxCddCRy_RtV \
    AUTH_HOST=david4096.auth0.com \
    python app.py

Other optional environment variables are:

* `SCOPE` - Learn about scopes: https://auth0.com/docs/scopes, defaults to 'openid email'
* `SECRET_KEY` - For initializing flask's session.
* `DEBUG` - defaults to True.
* `HOST` - defaults to localhost.
* `PORT` - defaults to 5000.

## Description

The application is served from one file and two templates.

The first and most important is `app.py` which uses inline comments to describe what is happening. It has been derived
from python examples available [here](https://auth0.com/docs/quickstart/backend/python).

The first template, `templates/login.html` serves from the root directory and requests for the user to login using
a provided JavaScript module. This module will communicate with Auth0 to populate the list of available login methods 
when combined with `SCOPE`.

The second template, `templates/key.html` shows the resulting signed `id_token` that has a life span configurable using
the Auth0 administration panel. It attempts to make to the requests to the `/protected` endpoint every second and renders the response. A logout button is provided.

## Notes

Web tokens are signed JSON that can be used to guarantee identity, however, a server is required to maintain it's own state regarding logins. Different APIs manage their keys differently, offering TTL, changes in authorization level, etc.

In this example, we use an in-memory cache to store and drop keys. In a practical application, this should be managed in a distributed cache or database.

It has not been tested if the `logout` functionality is changing any state in Auth0, if a user wants to log back in they must be issued a new key. To read more about refreshing tokens visit [Understanding Refresh Tokens](https://auth0.com/learn/refresh-tokens/).