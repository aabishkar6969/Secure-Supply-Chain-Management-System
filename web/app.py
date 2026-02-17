from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
import os
import json
import click
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import sys
import os
# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ca import create_root_ca
from core.supply_chain import create_participant, sign_shipment_event, verify_shipment_event

app = Flask(__name__)
app.secret_key = 'your-secret-key-for-flask-sessions'  # Change in production!

# Ensure CA exists
CA_KEY_PATH = "ca.key"
CA_CERT_PATH = "ca.crt"

if not os.path.exists(CA_KEY_PATH) or not os.path.exists(CA_CERT_PATH):
    print("⚠️ CA not initialized. Running CA init...")
    priv_key, cert = create_root_ca("Secure Supply Chain Root CA")
    with open(CA_KEY_PATH, "wb") as f:
        f.write(priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(CA_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("✅ CA initialized.")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        subject = request.form.get('subject')
        password = request.form.get('password')
        if not subject or not password:
            flash('Subject and password are required!', 'error')
            return redirect(url_for('register'))

        try:
            with open(CA_KEY_PATH, "rb") as f:
                ca_priv_key = load_pem_private_key(f.read(), password=None)
            with open(CA_CERT_PATH, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())

            out_file = f"{subject.replace(' ', '_')}.p12"
            cert = create_participant(ca_priv_key, ca_cert, subject, password.encode(), out_file)

            # Save certificate
            cert_file = f"{Path(out_file).stem}.crt"
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            flash(f'✅ Participant "{subject}" registered successfully!', 'success')
            return redirect(url_for('register'))
        except Exception as e:
            flash(f'❌ Error: {str(e)}', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/sign', methods=['GET', 'POST'])
def sign():
    if request.method == 'POST':
        key_file = request.files.get('key_file')
        password = request.form.get('password')
        event_file = request.files.get('event_file')

        if not key_file or not password or not event_file:
            flash('All fields are required!', 'error')
            return redirect(url_for('sign'))

        try:
            # Save uploaded files temporarily
            key_path = os.path.join('uploads', key_file.filename)
            event_path = os.path.join('uploads', event_file.filename)
            os.makedirs('uploads', exist_ok=True)
            key_file.save(key_path)
            event_file.save(event_path)

            with open(event_path) as f:
                event_data = json.load(f)

            sig = sign_shipment_event(event_data, key_path, password.encode())

            # Save signature
            sig_path = event_path.replace('.json', '.sig')
            with open(sig_path, "wb") as f:
                f.write(sig)

            flash('✅ Signature created successfully!', 'success')
            return send_from_directory(os.path.dirname(sig_path), os.path.basename(sig_path), as_attachment=True)

        except Exception as e:
            flash(f'❌ Error: {str(e)}', 'error')
            return redirect(url_for('sign'))

    return render_template('sign.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        cert_file = request.files.get('cert_file')
        sig_file = request.files.get('sig_file')
        event_file = request.files.get('event_file')

        if not cert_file or not sig_file or not event_file:
            flash('All files are required!', 'error')
            return redirect(url_for('verify'))

        try:
            # Save uploaded files temporarily
            cert_path = os.path.join('uploads', cert_file.filename)
            sig_path = os.path.join('uploads', sig_file.filename)
            event_path = os.path.join('uploads', event_file.filename)
            os.makedirs('uploads', exist_ok=True)
            cert_file.save(cert_path)
            sig_file.save(sig_path)
            event_file.save(event_path)

            with open(event_path) as f:
                event_data = json.load(f)
            with open(sig_path, "rb") as f:
                signature = f.read()

            valid = verify_shipment_event(event_data, signature, cert_path)

            if valid:
                flash('✅ Verification successful! The signature is valid.', 'success')
            else:
                flash('❌ Signature invalid — data tampered or fake!', 'error')

        except Exception as e:
            flash(f'❌ Error: {str(e)}', 'error')

        return redirect(url_for('verify'))

    return render_template('verify.html')

if __name__ == '__main__':
    app.run(debug=True)