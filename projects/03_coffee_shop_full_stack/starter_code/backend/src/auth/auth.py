import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'xadahiya.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'https://udacity-coffee-shop.com'

# AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


# Auth Header

'''
@TODO implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''


def get_token_auth_header(request):
    if 'Authorization' not in request.headers.keys():
        raise AuthError("No Authoriztion header found", 401)
    auth_header = request.headers['Authorization']
    if len(auth_header.split(" ")) != 2:
        raise AuthError("Malformed header", 401)

    token = auth_header.split(" ")[1]
    return token

'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission
    string is not in the payload permissions array
    return true otherwise
'''


def check_permissions(permission, payload):

    if permission not in payload["permissions"]:
        raise AuthError("Operation not allowed", 401)
    return True
'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here:
'''


def verify_decode_jwt(token):
    try:
        jwk = json.loads(urlopen(
            "https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")
            .read())["keys"]
    except:
        raise AuthError("Unable to get JWKs", 500)
    unverified_header = jwt.get_unverified_header(token)
    verified_key = None
    for k in jwk:
        if unverified_header['kid'] == k['kid']:
            verified_key = k

    if not verified_key:
        raise AuthError("Wrong Kid", 401)
    try:
        payload = jwt.decode(
                token,
                json.dumps(verified_key),
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer="https://" + AUTH0_DOMAIN + "/"
                )
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("token is expired", 401)
    except (jwt.InvalidAudienceError, jwt.InvalidIssuerError):
        raise AuthError("Incorrect claims, check the audience and issuer", 401)
    except Exception:
        raise AuthError("Unable to parse authentication token.", 401)


'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and
    check the requested permission
    return the decorator which passes the decoded payload to the
    decorated method
'''


def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if permission != '':
                token = get_token_auth_header(request)
                payload = verify_decode_jwt(token)
                check_permissions(permission, payload)
            return f(*args, **kwargs)

        return wrapper
    return requires_auth_decorator
