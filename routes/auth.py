import re
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, jsonify
from sqlalchemy.exc import IntegrityError
from models.user import User, RefreshToken
from db.database import db
from utils.security import hash_password, verify_password, limiter
from flask_jwt_extended import (
    create_access_token, 
    create_refresh_token, 
    jwt_required, 
    get_jwt_identity, 
    get_jwt,
    decode_token,
    set_access_cookies,
    unset_jwt_cookies,
    set_refresh_cookies
)

auth_bp = Blueprint("auth", __name__)

# Basic regex for email validation
EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")

@auth_bp.route("/register", methods=["POST"])
@limiter.limit("5 per minute") # Added rate limit to prevent bot spam
def register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
        
    if not EMAIL_REGEX.match(email):
        return jsonify({"error": "Invalid email format"}), 400
        
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "User already exists"}), 400

    hashed_password = hash_password(password)

    new_user = User(
        email=email,
        password_hash=hashed_password
    )

    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "A database error occurred or user already exists"}), 500

    return jsonify({"message": "User registered successfully"}), 201



@auth_bp.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    user = User.query.filter_by(email=email).first()

    if user and verify_password(password, user.password_hash):
        identity = str(user.id)
        response = jsonify({"message": "Login successful"})
        
        access_token = create_access_token(identity=identity)
        refresh_token = create_refresh_token(identity=identity)
        
        jti = decode_token(refresh_token)["jti"]

        new_token = RefreshToken(
            token=jti,
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7) 
        )
        db.session.add(new_token)
        db.session.commit()
        
        set_access_cookies(response, access_token)
        set_refresh_cookies(response, refresh_token)
        
        return response, 200

    return jsonify({"error": "Invalid credentials"}), 401



@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    jwt_payload = get_jwt()
    token_jti = jwt_payload["jti"]
    
    token_record = RefreshToken.query.filter_by(token=token_jti).first()
    
    if not token_record or token_record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return jsonify({"error": "Refresh token is invalid or has been revoked"}), 401

    access_token = create_access_token(identity=identity)
    response = jsonify({"message": "Refresh request successful"})
    set_access_cookies(response, access_token)
    return response, 200
    
    


@auth_bp.route("/logout", methods=["POST"])
@jwt_required(refresh=True)
def logout():
    jwt_payload = get_jwt()
    token_jti = jwt_payload["jti"]

    token = RefreshToken.query.filter_by(token=token_jti).first()
    if token:
        db.session.delete(token)
        db.session.commit()
        
    response = jsonify({"message": "Logged out successful"})
    unset_jwt_cookies(response)
    return response, 200


