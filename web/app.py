import os
import json
from flask import Flask, render_template, request, redirect, url_for, flash
from cryptography.hazmat.primitives import serialization
from core.ca import create_root_ca, issue_certificate
from core.crypto import sign_data, verify_signature, save_pkcs12, load_pkcs12
from .models import db, Participant, Shipment

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'supplychain-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../instance/app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    
    with app.app_context():
        os.makedirs('instance', exist_ok=True)
        db.create_all()
        
        # Initialize CA if not exists
        if not os.path.exists('ca.key'):
            ca_key, ca_cert = create_root_ca("SecureSupplyChain CA")
            with open("ca.key", "wb") as f:
                f.write(ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open("ca.crt", "wb") as f:
                f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    
    return app

app = create_app()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        if not name:
            flash('Name is required!', 'danger')
            return render_template('register.html')
        
        if Participant.query.filter_by(name=name).first():
            flash('Participant already exists!', 'danger')
            return render_template('register.html')
        
        # Load CA
        with open('ca.key', 'rb') as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open('ca.crt', 'rb') as f:
            ca_cert = serialization.load_pem_x509_certificate(f.read())
        
        # Issue certificate
        priv_key, cert = issue_certificate(ca_key, ca_cert, name)
        
        # Save as PKCS#12 (password = "demo123" for demo)
        p12_data = save_pkcs12(priv_key, cert, b"demo123", f"{name}.p12")
        
        # Save to DB
        participant = Participant(
            name=name,
            certificate=cert.public_bytes(serialization.Encoding.PEM).decode(),
            private_key_p12=p12_data
        )
        db.session.add(participant)
        db.session.commit()
        
        flash(f'✅ {name} registered successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/sign', methods=['GET', 'POST'])
def sign():
    participants = Participant.query.all()
    if request.method == 'POST':
        sender_name = request.form['sender']
        receiver_name = request.form['receiver']
        batch_id = request.form['batch_id']
        product = request.form['product']
        
        sender = Participant.query.filter_by(name=sender_name).first()
        receiver = Participant.query.filter_by(name=receiver_name).first()
        
        if not sender or not receiver:
            flash('Invalid sender or receiver!', 'danger')
            return render_template('sign.html', participants=participants)
        
        # Create shipment data
        shipment_data = {
            "batch_id": batch_id,
            "product": product,
            "from": sender_name,
            "to": receiver_name,
            "timestamp": "2025-12-13T10:00:00Z"
        }
        data_bytes = json.dumps(shipment_data, sort_keys=True).encode()
        
        # Sign with sender's private key
        priv_key, _ = load_pkcs12(sender.private_key_p12, b"demo123")
        signature = sign_data(data_bytes, priv_key)
        
        # Save shipment
        shipment = Shipment(
            batch_id=batch_id,
            product=product,
            sender_id=sender.id,
            receiver_id=receiver.id,
            data_json=json.dumps(shipment_data),
            signature=signature
        )
        db.session.add(shipment)
        db.session.commit()
        
        flash('✅ Shipment signed successfully!', 'success')
        return redirect(url_for('verify', shipment_id=shipment.id))
    
    return render_template('sign.html', participants=participants)

@app.route('/verify/<int:shipment_id>', methods=['GET', 'POST'])
def verify(shipment_id):
    shipment = Shipment.query.get_or_404(shipment_id)
    sender = Participant.query.get(shipment.sender_id)
    
    if request.method == 'POST':
        # Simulate tamper
        shipment.is_tampered = True
        db.session.commit()
        return redirect(url_for('verify', shipment_id=shipment_id))
    
    # Verify signature
    data_bytes = shipment.data_json.encode()
    cert = serialization.load_pem_x509_certificate(sender.certificate.encode())
    is_valid = verify_signature(data_bytes, shipment.signature, cert.public_key())
    
    if shipment.is_tampered:
        is_valid = False
    
    return render_template('verify.html', 
                         shipment=shipment, 
                         sender=sender, 
                         is_valid=is_valid,
                         tampered=shipment.is_tampered)

if __name__ == '__main__':
    app.run(debug=True)