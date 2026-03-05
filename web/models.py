from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Participant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    certificate = db.Column(db.Text, nullable=False)
    private_key_p12 = db.Column(db.LargeBinary, nullable=False)

class Shipment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.String(50), nullable=False)
    product = db.Column(db.String(100), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('participant.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('participant.id'), nullable=False)
    data_json = db.Column(db.Text, nullable=False)
    signature = db.Column(db.LargeBinary, nullable=False)
    is_tampered = db.Column(db.Boolean, default=False)