from fastapi import FastAPI, HTTPException, Request, Depends, Form, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from registration import register_intern, register_campaign_manager
from db import db
from auth import authenticate_user, create_access_token, get_current_user, change_password, forgot_password, reset_password
from datetime import timedelta
import uvicorn

app = FastAPI()

# Allow CORS for glovn.com
origins = [
    "http://localhost:5173",
    "http://glovn.com",
    "https://glovn.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.post("/register/intern")
async def register_intern_endpoint(request: Request):
    data = await request.json()
    email = data.get("email")
    password = data.get("password")
    return register_intern(email, password)


@app.post("/register/campaign")
async def register_campaign_manager_endpoint(request: Request):
    data = await request.json()
    email = data.get("email")
    password = data.get("password")
    return register_campaign_manager(email, password)


@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=400,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token}


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/change-password")
async def change_password_endpoint(
    current_password: str = Form(...),
    new_password: str = Form(...),
    token: str = Depends(oauth2_scheme)
):
    try:
        current_user = get_current_user(token)
    except HTTPException as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication error: {str(e)}"
        )

    try:
        result = change_password(current_user, current_password, new_password)
        return result
    except HTTPException as e:
        raise e


@app.post("/forgot-password")
def forgot_password_route(email: str = Form(...)):
    return forgot_password(email)

@app.post("/reset-password/{token}")
def reset_password_route(token: str, new_password: str = Form(...)):
    return reset_password(token, new_password)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
