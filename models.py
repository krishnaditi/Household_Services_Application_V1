from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class Customer(db.Model):
    __tablename__ = 'customers'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Store hashed passwords
    is_blocked = db.Column(db.Boolean, default=False)  # For block/unblock functionality
    
    # Relationship to ServiceRequest
    service_requests = db.relationship('ServiceRequest', back_populates='customer', cascade="all, delete-orphan")

    # Password methods (optional but recommended for handling password hashing and checking)
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class ServiceProfessional(db.Model):
    __tablename__ = 'service_professionals'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    password = db.Column(db.String(200), nullable=False)  # Store hashed passwords
    service_type = db.Column(db.String(50), nullable=False)
    experience = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(100), nullable=True)
    pincode = db.Column(db.String(10), nullable=True)
    approved = db.Column(db.Boolean, default=False)  # Approval status for admin
    is_blocked = db.Column(db.Boolean, default=False)  # For block/unblock functionality
    
    # Relationship to ServiceRequest
    service_requests = db.relationship('ServiceRequest', back_populates='professional', cascade="all, delete-orphan")

    # Password methods
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Admin(db.Model):
    __tablename__ = 'admins'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    
    # Relationship to Service
    services = db.relationship('Service', back_populates='created_by_admin', cascade="all, delete-orphan")


class Service(db.Model):
    __tablename__ = 'services'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    time_required = db.Column(db.Integer, nullable=False)  # Time required in minutes
    description = db.Column(db.Text)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)
    
    # Relationship to Admin
    created_by_admin = db.relationship('Admin', back_populates='services')
    
    # Relationship to ServiceRequest
    service_requests = db.relationship('ServiceRequest', back_populates='service', cascade="all, delete-orphan")


class ServiceRequest(db.Model):
    __tablename__ = 'service_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('service_professionals.id'), nullable=True)
    
    date_of_request = db.Column(db.DateTime, default=datetime.utcnow)
    date_of_completion = db.Column(db.DateTime, nullable=True)
    service_status = db.Column(db.String(20), nullable=False, default="requested")
    remarks = db.Column(db.Text, nullable=True)
    
    # Relationships with back_populates
    customer = db.relationship('Customer', back_populates='service_requests')
    professional = db.relationship('ServiceProfessional', back_populates='service_requests')
    service = db.relationship('Service', back_populates='service_requests')

