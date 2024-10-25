from fastapi import HTTPException
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from db import db
from pydantic import BaseModel
from email_service import send_password_reset_email

# Secret key to encode the JWT token
SECRET_KEY = "your_secret_key"  # Replace with a secure secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Ensure bcrypt is correctly configured
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(email: str, password: str):
    interns_collection = db['interns']
    campaigns_collection = db['campaigns']
    
    user = interns_collection.find_one({"email": email})
    if not user:
        user = campaigns_collection.find_one({"email": email})
    if not user or not verify_password(password, user['password']):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def change_password(current_user: dict, current_password: str, new_password: str):
    if not verify_password(current_password, current_user['password']):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    hashed_password = hash_password(new_password)
    if current_user['role'] == 'intern':
        db['interns'].update_one({"email": current_user['email']}, {"$set": {"password": hashed_password}})
    else:
        db['campaigns'].update_one({"email": current_user['email']}, {"$set": {"password": hashed_password}})
    
    return {"message": "Password changed successfully"}


def get_user_by_email(email: str):
    user = db['interns'].find_one({"email": email})
    if not user:
        user = db['campaigns'].find_one({"email": email})
    return user


def get_current_user(token: str):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    email: str = payload.get("sub")

    user = get_user_by_email(email)

    return user


def create_password_reset_token(email: str):
    expires_delta = timedelta(hours=1)
    reset_token = create_access_token(data={"sub": email, "type": "reset"}, expires_delta=expires_delta)
    return reset_token

def forgot_password(email: str):
    user = get_user_by_email(email)
    if user:
        reset_token = create_password_reset_token(email)
        reset_link = f"https://glovn.com/reset-password/{reset_token}"
        send_password_reset_email(email, reset_link)
    # Always return the same message, whether the email exists or not
    return {"message": "Password reset instructions sent to email if account exists."}

def reset_password(token: str, new_password: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if payload.get("type") != "reset":
            raise HTTPException(status_code=400, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")

    user = get_user_by_email(email)
    if user:
        hashed_password = hash_password(new_password)
        if user['role'] == 'intern':
            db['interns'].update_one({"email": email}, {"$set": {"password": hashed_password}})
        else:
            db['campaigns'].update_one({"email": email}, {"$set": {"password": hashed_password}})

    # Always return a success message, whether the user exists or not
    return {"message": "If the account exists, the password has been reset successfully"}
