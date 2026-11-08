import hashlib
import hmac

import pytest

from app.core import *


def test_modexp_matches_reference_for_fixed_vectors():
    for base, exponent, modulus in [(5, 12345, P), (123, 0, 7919), (987654, 321, 1000003)]:
        assert modexp(base, exponent, modulus) == pow(base, exponent, modulus)


def test_modexp_rejects_invalid_inputs():
    with pytest.raises(ValueError):
        modexp(2, -1)
    with pytest.raises(ValueError):
        modexp(2, 1, 1)


def test_dh_shared_key_matches_on_both_sides():
    a, ap = dh_keypair()
    b, bp = dh_keypair()
    assert dh_shared(a, bp) == dh_shared(b, ap)


def test_dh_rejects_small_public_values():
    with pytest.raises(ValueError):
        dh_shared(2, 1)
    with pytest.raises(ValueError):
        dh_shared(1, 2)


def test_sha256_known_vectors_against_reference_library():
    assert sha256(b"abc").hex() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    for data in [b"", b"abc", b"The quick brown fox jumps over the lazy dog", bytes(range(256))]:
        assert sha256(data).hex() == hashlib.sha256(data).hexdigest()


def test_hmac_sha256_known_vector_against_reference_library():
    key = bytes.fromhex("0b" * 20)
    data = b"Hi There"
    expected = hmac.new(key, data, hashlib.sha256).hexdigest()
    assert hmac_sha256(key, data).hex() == expected


def test_stream_cipher_matches_independent_reference():
    text = "你好, Alice"
    shared = 12345
    nonce = "abc"
    assert crypt(text, shared, nonce) == "3828e9de1fe6e0d5193a0d45f8"
    key = hashlib.sha256(f"mitm-lab:{shared}".encode()).digest()
    expected = bytearray()
    for i, byte in enumerate(text.encode()):
        stream = hashlib.sha256(key + nonce.encode() + (i // 32).to_bytes(4, "big")).digest()
        expected.append(byte ^ stream[i % 32])
    assert crypt(text, shared, nonce) == expected.hex()
    assert decrypt(expected.hex(), shared, nonce) == text


def test_wrong_key_does_not_recover_plaintext():
    text = "hello"
    ciphertext = crypt(text, 12345, "abc")
    try:
        recovered = decrypt(ciphertext, 54321, "abc")
    except UnicodeDecodeError:
        return
    assert recovered != text


def test_tag_matches_independent_hmac_reference_and_detects_changes():
    ciphertext = crypt("hello", 12345, "abc")
    key = hashlib.sha256(f"mitm-lab:{12345}".encode()).digest()
    expected = hmac.new(key, f"abc:{ciphertext}".encode(), hashlib.sha256).hexdigest()
    assert tag(ciphertext, 12345, "abc") == expected
    assert tag(ciphertext[:-2] + "00", 12345, "abc") != expected
