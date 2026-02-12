import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.crypto import sign_data, verify_signature, hybrid_encrypt, hybrid_decrypt, save_pkcs12, load_pkcs12
from core.ca import create_root_ca, create_participant
import tempfile
import pytest

# ── Setup ──────────────────────────────────────────────────────────────
@pytest.fixture
def ca():
    return create_root_ca("TestCA")

@pytest.fixture
def participant(ca):
    private_key, cert = ca
    return create_participant("TestUser", private_key, cert)

# ── Functional Tests ───────────────────────────────────────────────────
def test_rsa_key_generation(ca):
    private_key, cert = ca
    assert private_key is not None
    assert cert is not None

def test_sign_and_verify_valid(ca):
    private_key, cert = ca
    data = b"shipment_event_data"
    signature = sign_data(data, private_key)
    assert verify_signature(data, signature, cert.public_key()) == True

def test_verify_fails_on_tampered_data(ca):
    private_key, cert = ca
    data = b"original_data"
    signature = sign_data(data, private_key)
    tampered = b"tampered_data"
    assert verify_signature(tampered, signature, cert.public_key()) == False

def test_verify_fails_on_corrupted_signature(ca):
    private_key, cert = ca
    data = b"some_data"
    signature = sign_data(data, private_key)
    corrupted = b"0" * len(signature)
    assert verify_signature(data, corrupted, cert.public_key()) == False

def test_hybrid_encrypt_decrypt_roundtrip(ca):
    private_key, cert = ca
    plaintext = b"sensitive shipment payload"
    encrypted = hybrid_encrypt(plaintext, cert.public_key())
    decrypted = hybrid_decrypt(encrypted, private_key)
    assert decrypted == plaintext

def test_hybrid_encrypt_produces_different_ciphertext(ca):
    private_key, cert = ca
    plaintext = b"same data"
    enc1 = hybrid_encrypt(plaintext, cert.public_key())
    enc2 = hybrid_encrypt(plaintext, cert.public_key())
    assert enc1['ciphertext'] != enc2['ciphertext']

def test_pkcs12_save_and_load(ca, tmp_path):
    private_key, cert = ca
    p12_path = str(tmp_path / "test.p12")
    password = b"testpassword"
    save_pkcs12(private_key, cert, password, p12_path)
    loaded_key, loaded_cert = load_pkcs12(p12_path, password)
    assert loaded_key is not None
    assert loaded_cert is not None

def test_pkcs12_wrong_password_fails(ca, tmp_path):
    private_key, cert = ca
    p12_path = str(tmp_path / "test.p12")
    save_pkcs12(private_key, cert, b"correctpassword", p12_path)
    with pytest.raises(Exception):
        load_pkcs12(p12_path, b"wrongpassword")

# ── Attack Simulation Tests ────────────────────────────────────────────
def test_wrong_certificate_fails(ca):
    private_key1, cert1 = ca
    private_key2, cert2 = create_root_ca("AnotherCA")
    data = b"shipment_data"
    signature = sign_data(data, private_key1)
    assert verify_signature(data, signature, cert2.public_key()) == False

def test_empty_signature_fails(ca):
    private_key, cert = ca
    data = b"some_data"
    assert verify_signature(data, b"", cert.public_key()) == False

def test_replay_produces_different_signature(ca):
    private_key, cert = ca
    data = b"same event"
    sig1 = sign_data(data, private_key)
    sig2 = sign_data(data, private_key)
    assert sig1 != sig2