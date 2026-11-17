"""Tests offline de las fuentes passivas nuevas (JWT/JWK/DNSSEC)."""

from pq_cbom.passive_scanner import _DNSSEC_ALG, _map_jwk_kty, _map_jwt_alg


def test_map_jwt_alg():
    assert _map_jwt_alg("RS256") == "RSA"
    assert _map_jwt_alg("PS512") == "RSA"
    assert _map_jwt_alg("ES256") == "ECDSA"
    assert _map_jwt_alg("EdDSA") == "Ed25519"
    assert _map_jwt_alg("HS256") == "HMAC"
    assert _map_jwt_alg("none") is None


def test_map_jwk_kty():
    assert _map_jwk_kty("RSA") == "RSA"
    assert _map_jwk_kty("EC") == "ECDSA"
    assert _map_jwk_kty("OKP") == "Ed25519"
    assert _map_jwk_kty("oct") == "HMAC"
    assert _map_jwk_kty("???") is None


def test_dnssec_algorithm_map():
    assert _DNSSEC_ALG["8"] == "RSA"     # RSA/SHA-256
    assert _DNSSEC_ALG["13"] == "ECDSA"  # ECDSA P-256
    assert _DNSSEC_ALG["15"] == "Ed25519"
    assert _DNSSEC_ALG["3"] == "DSA"
