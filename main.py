# Carsen Moore
# cpm0153

import base64, uuid
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# create a fastapi web server
app = FastAPI()

# this list stores all rsa keys we generate
# each item is a dict: {"private": ..., "kid": ..., "expiry": ...}
keys = []


# make a new rsa key pair and save it in the global list
# param expiry: datetime when the key should expire
# return: the new key dict
def new_key(expiry):
    # generate a 2048-bit rsa private key
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # generate a random unique key id (kid)
    kid = uuid.uuid4().hex
    # store the private key, kid, and expiry in a dict
    k = {"private": private, "kid": kid, "expiry": expiry}
    # add the key to the list of keys
    keys.append(k)
    return k


# at startup, create one valid key (good for 24 hours)
new_key(datetime.now(timezone.utc) + timedelta(hours=24))
# also create one expired key (expired 1 hour ago)
new_key(datetime.now(timezone.utc) - timedelta(hours=1))


# check if a key has expired
# param k: a key dict
# return: True if the current time is past the expiry
def is_expired(k):
    return datetime.now(timezone.utc) >= k["expiry"]


# convert an integer into base64url (needed for jwk encoding)
# param n: integer (like rsa modulus or exponent)
# return: base64url string without padding
def b64url(n):
    # convert int -> bytes -> base64url string
    return base64.urlsafe_b64encode(
        n.to_bytes((n.bit_length() + 7) // 8, "big")
    ).rstrip(b"=").decode()


# turn a key dict into a jwk (json web key) with only public info
# param k: a key dict
# return: a dict in jwk format (alg, kid, n, e, etc.)
def make_jwk(k):
    # get the public rsa numbers (n and e)
    nums = k["private"].public_key().public_numbers()
    return {
        "kty": "RSA",       # key type
        "kid": k["kid"],    # key id
        "use": "sig",       # key is used for signing
        "alg": "RS256",     # signing algorithm
        "n": b64url(nums.n),# modulus encoded
        "e": b64url(nums.e) # exponent encoded
    }


# serve the jwks (set of public keys)
# only include keys that are not expired
# exposed on both /jwks and /.well-known/jwks.json
@app.get("/jwks")
@app.get("/.well-known/jwks.json")
def jwks():
    # build a list of jwks for all non-expired keys
    return {"keys": [make_jwk(k) for k in keys if not is_expired(k)]}


# issue a jwt token
# accepts POST requests on /auth
# if query param "expired" is present -> use an expired key
# otherwise -> use a valid key
@app.post("/auth")
def auth(req: Request):
    # check if user asked for an expired token
    use_exp = "expired" in req.query_params

    # try to find a key that matches the request (expired or not)
    key = next((k for k in keys if is_expired(k) == use_exp), None)

    # if no suitable key exists, make one
    if not key:
        expiry = (
            datetime.now(timezone.utc) - timedelta(hours=1)  # expired 1h ago
            if use_exp else
            datetime.now(timezone.utc) + timedelta(hours=24) # valid for 24h
        )
        key = new_key(expiry)

    # now = current utc time
    now = datetime.now(timezone.utc)
    # claims for the jwt
    claims = {
        "iat": int(now.timestamp()),           # issued at
        "exp": int(key["expiry"].timestamp()), # expiration matches key expiry
    }

    # turn the private key into pem bytes for jwt signing
    pem = key["private"].private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    # sign the jwt with rs256 and include the kid in the header
    token = jwt.encode(claims, pem, algorithm="RS256", headers={"kid": key["kid"]})

    # return json with the token
    return JSONResponse({"token": token})
