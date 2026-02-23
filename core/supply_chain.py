# core/supply_chain.py
import json
from cryptography.x509 import load_pem_x509_certificate
from .ca import issue_certificate
from .crypto import sign_data, verify_signature, save_pkcs12, load_pkcs12

def create_participant(ca_key, ca_cert, name: str, password: bytes, out_p12: str):
    """Create a participant with certificate and private key in PKCS#12 format."""
    priv_key, cert = issue_certificate(ca_key, ca_cert, name)
    save_pkcs12(priv_key, cert, password, out_p12)
    return cert

def sign_shipment_event(event_dict: dict, p12_file: str, password: bytes):
    """Sign a shipment event using participant's private key."""
    data = json.dumps(event_dict, sort_keys=True).encode()
    priv_key, _ = load_pkcs12(p12_file, password)
    return sign_data(data, priv_key)

def verify_shipment_event(event_dict: dict, signature: bytes, cert_file: str):
    """Verify a signed shipment event using participant's certificate."""
    data = json.dumps(event_dict, sort_keys=True).encode()
    with open(cert_file, "rb") as f:
        cert = load_pem_x509_certificate(f.read())
    return verify_signature(data, signature, cert.public_key())