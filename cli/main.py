# cli/main.py
import os
import json
import click
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from core.ca import create_root_ca
from core.supply_chain import create_participant, sign_shipment_event, verify_shipment_event

@click.group()
def cli():
    """Secure Supply Chain Management System"""
    pass

@cli.group()
def ca():
    """Certificate Authority operations"""
    pass

@ca.command()
@click.option('--name', required=True, help="CA Common Name")
def init(name):
    priv_key, cert = create_root_ca(name)
    with open("ca.key", "wb") as f:
        f.write(priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("ca.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    click.echo("✅ CA initialized: ca.key, ca.crt")

@cli.command()
@click.option('--subject', required=True, help="Participant name")
@click.password_option()
@click.option('--out', default=None)
def register(subject, password, out):
    with open("ca.key", "rb") as f:
        ca_priv_key = load_pem_private_key(f.read(), password=None)
    with open("ca.crt", "rb") as f:
        ca_cert = load_pem_x509_certificate(f.read())
    out_file = out or f"{subject.replace(' ', '_')}.p12"
    cert = create_participant(ca_priv_key, ca_cert, subject, password.encode(), out_file)
    
    # ✅ Extract certificate WITHOUT OpenSSL
    cert_file = f"{Path(out_file).stem}.crt"
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    click.echo(f"✅ Participant '{subject}' registered: {out_file} + {cert_file}")

@cli.command()
@click.option('--key', required=True, type=click.Path(exists=True))
@click.password_option()
@click.option('--event', required=True, type=click.Path(exists=True))
@click.option('--output', default=None)
def sign(key, password, event, output):
    with open(event) as f:
        event_data = json.load(f)
    sig = sign_shipment_event(event_data, key, password.encode())
    out_file = output or f"{Path(event).stem}.sig"
    with open(out_file, "wb") as f:
        f.write(sig)
    click.echo(f"✅ Signed → {out_file}")

@cli.command()
@click.option('--cert', required=True, type=click.Path(exists=True))
@click.option('--sig', required=True, type=click.Path(exists=True))
@click.option('--event', required=True, type=click.Path(exists=True))
def verify(cert, sig, event):
    with open(event) as f:
        event_data = json.load(f)
    with open(sig, "rb") as f:
        signature = f.read()
    valid = verify_shipment_event(event_data, signature, cert)
    if valid:
        click.echo("✅ Verification successful!")
    else:
        click.echo("❌ Signature invalid — data tampered or fake!", err=True)
        raise click.Abort()

if __name__ == '__main__':
    cli()