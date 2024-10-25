from fastapi import HTTPException
from db import db
from email_service import send_registration_email
from auth import hash_password


def register_intern(email: str, password: str):
    interns_collection = db['interns']
    
    if interns_collection.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hash_password(password)
    intern_data = {"email": email, "password": hashed_password, "role": "intern"}
    interns_collection.insert_one(intern_data)
    send_registration_email(email)
    return {"message": "Intern registered successfully"}


def register_campaign_manager(email: str, password: str):
    campaigns_collection = db['campaigns']
    
    if campaigns_collection.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hash_password(password)
    campaign_manager_data = {"email": email, "password": hashed_password, "role": "campaign"}
    campaigns_collection.insert_one(campaign_manager_data)
    send_registration_email(email)
    return {"message": "Campaign manager registered successfully"}
