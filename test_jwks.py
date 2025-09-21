import pytest
from fastapi.testclient import TestClient
import jwt
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization

from main import app, keys, is_expired  # import from main.py

client = TestClient(app)


# test that /jwks only returns unexpired keys
def test_jwks_only_has_unexpired_keys():
    res = client.get("/jwks")
    assert res.status_code == 200
    body = res.json()
    # all keys returned should not be expired
    for jwk in body["keys"]:
        # make sure kid matches an unexpired key
        match = next((k for k in keys if k["kid"] == jwk["kid"]), None)
        assert match is not None
        assert not is_expired(match)


# test that /auth issues a valid jwt signed by an unexpired key
def test_auth_returns_valid_jwt():
    res = client.post("/auth")
    assert res.status_code == 200
    token = res.json()["token"]

    # decode token using the public key from jwks
    jwks = client.get("/jwks").json()["keys"]
    header = jwt.get_unverified_header(token)
    kid = header["kid"]
    jwk = next(k for k in jwks if k["kid"] == kid)

    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
    claims = jwt.decode(token, public_key, algorithms=["RS256"])
    
    # check claims are present and valid
    assert "iat" in claims
    assert "exp" in claims
    assert claims["exp"] > datetime.now(timezone.utc).timestamp()


# test that /auth?expired=true issues a jwt signed with an expired key
def test_auth_expired_returns_expired_jwt():
    res = client.post("/auth?expired=true")
    assert res.status_code == 200
    token = res.json()["token"]

    # decode without verifying exp so we can inspect it
    header = jwt.get_unverified_header(token)
    kid = header["kid"]

    # expired key should not be in jwks
    jwks = client.get("/jwks").json()["keys"]
    assert not any(k["kid"] == kid for k in jwks)

    # get the expired key's private key
    private_key = next(k for k in keys if k["kid"] == kid)["private"]

    # turn the public key into pem for verification
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # decode claims ignoring expiration
    claims = jwt.decode(token, pem, algorithms=["RS256"], options={"verify_exp": False})

    # the exp claim should already be in the past
    assert claims["exp"] < datetime.now(timezone.utc).timestamp()