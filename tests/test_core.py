import hashlib
import hmac

import pytest

from app.core import (
    G,
    P,
    constant_time_equal,
    crypt,
    decrypt,
    dh_keypair,
    dh_shared,
    hmac_sha256,
    modexp,
    sha256,
    tag,
)


def reference_stream_cipher(text: str, shared: int, nonce: str) -> str:
    """Independent reference for the lab's documented stream construction."""
    key = hashlib.sha256(f"mitm-lab:{shared}".encode()).digest()
    encrypted = bytearray()
    for index, byte in enumerate(text.encode()):
        block = hashlib.sha256(
            key + nonce.encode() + (index // 32).to_bytes(4, "big")
        ).digest()
        encrypted.append(byte ^ block[index % 32])
    return encrypted.hex()


@pytest.mark.parametrize(
    ("base", "exponent", "modulus"),
    [
        (0, 0, 2),
        (5, 12345, P),
        (123, 0, 7919),
        (987654, 321, 1000003),
        (-7, 19, 101),
    ],
)
def test_modexp_matches_python_pow(base, exponent, modulus):
    assert modexp(base, exponent, modulus) == pow(base, exponent, modulus)


def test_modexp_rejects_invalid_inputs():
    with pytest.raises(ValueError):
        modexp(2, -1)
    with pytest.raises(ValueError):
        modexp(2, 1, 1)


def test_dh_keypairs_and_shared_secret_match_modular_arithmetic():
    alice_private, alice_public = dh_keypair()
    bob_private, bob_public = dh_keypair()

    assert 2 <= alice_private <= P - 2
    assert 2 <= bob_private <= P - 2
    assert 2 <= alice_public <= P - 2
    assert 2 <= bob_public <= P - 2
    assert alice_public == pow(G, alice_private, P)
    assert bob_public == pow(G, bob_private, P)

    alice_shared = dh_shared(alice_private, bob_public)
    bob_shared = dh_shared(bob_private, alice_public)
    assert alice_shared == bob_shared
    assert alice_shared == pow(bob_public, alice_private, P)


def test_dh_generator_has_large_subgroup_order():
    # P is a safe prime, so this proves G=2 is not trapped in the small
    # order-two subgroup and cannot reproduce the old Mersenne-prime bug.
    assert pow(G, (P - 1) // 2, P) == P - 1


@pytest.mark.parametrize("private, public", [(1, 2), (P - 1, 2), (2, 1), (2, P - 1)])
def test_dh_rejects_out_of_range_values(private, public):
    with pytest.raises(ValueError):
        dh_shared(private, public)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"a",
        b"a" * 55,
        b"a" * 56,
        b"a" * 63,
        b"a" * 64,
        b"a" * 65,
        b"a" * 127,
        b"a" * 128,
        bytes(range(256)),
    ],
)
def test_sha256_matches_hashlib_for_padding_boundaries(data):
    assert sha256(data) == hashlib.sha256(data).digest()


@pytest.mark.parametrize(
    ("key", "data"),
    [
        (b"", b""),
        (b"key", b"message"),
        (b"k" * 63, b"message"),
        (b"k" * 64, b"message"),
        (b"k" * 65, b"message"),
        (bytes(range(100)), bytes(range(256))),
    ],
)
def test_hmac_sha256_matches_hmac_library(key, data):
    assert hmac_sha256(key, data) == hmac.new(key, data, hashlib.sha256).digest()


@pytest.mark.parametrize(
    ("text", "shared", "nonce"),
    [
        ("", 2, "n"),
        ("hello", 12345, "abc"),
        ("你好, Alice", 12345, "abc"),
        ("x" * 65, P - 7, "nonce-with-length"),
    ],
)
def test_stream_cipher_matches_independent_hashlib_reference(text, shared, nonce):
    ciphertext = crypt(text, shared, nonce)
    assert ciphertext == reference_stream_cipher(text, shared, nonce)
    assert decrypt(ciphertext, shared, nonce) == text


def test_stream_cipher_changes_when_key_or_nonce_changes():
    ciphertext = crypt("hello", 12345, "abc")
    assert crypt("hello", 54321, "abc") != ciphertext
    assert crypt("hello", 12345, "def") != ciphertext
    assert crypt("hello!", 12345, "abc") != ciphertext


def test_wrong_key_does_not_recover_plaintext():
    ciphertext = crypt("hello", 12345, "abc")
    assert decrypt(ciphertext, 54321, "abc", errors="replace") != "hello"


def test_tag_matches_hmac_library_and_authenticates_every_field():
    ciphertext = crypt("hello", 12345, "abc")
    key = hashlib.sha256(f"mitm-lab:{12345}".encode()).digest()
    expected = hmac.new(key, b"session-1:abc:" + ciphertext.encode(), hashlib.sha256)
    assert tag(ciphertext, 12345, "abc", "session-1") == expected.hexdigest()
    assert (
        tag(ciphertext[:-2] + "00", 12345, "abc", "session-1") != expected.hexdigest()
    )
    assert tag(ciphertext, 12345, "changed", "session-1") != expected.hexdigest()
    assert tag(ciphertext, 12345, "abc", "session-2") != expected.hexdigest()


def test_constant_time_equal_matches_equality_contract():
    assert constant_time_equal("abc", "abc") is True
    assert constant_time_equal("abc", "abd") is False
    assert constant_time_equal("abc", "abcd") is False
