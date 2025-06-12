#!/usr/bin/env python3
import os
import time
import random
from dotenv import load_dotenv
from fastapi import (
    FastAPI, BackgroundTasks, Depends, HTTPException
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import jwt
import uvicorn

from .redis_client import r
from .email_utils   import send_email_otp

# ─── Load env & constants ─────────────────────────────
load_dotenv()
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-for-prod")
JWT_ALG    = os.getenv("JWT_ALG", "HS256")
ACCESS_TTL = int(os.getenv("ACCESS_TTL", 3600))

# ─── Crypto helpers ───────────────────────────────────
pwdctx = CryptContext(schemes=["argon2","bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="token")

def hash_pw(pw: str) -> str:
    return pwdctx.hash(pw)

def verify_pw(pw: str, hpw: str) -> bool:
    return pwdctx.verify(pw, hpw)

def jwt_encode(data: dict, ttl: int) -> str:
    payload = {**data, "exp": time.time() + ttl}
    return jwt.encode(payload, JWT_SECRET, JWT_ALG)

def jwt_decode(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, [JWT_ALG])
    except:
        return {}

# ─── User storage helpers ─────────────────────────────
def _user_key(uid: int) -> str:        return f"user:{uid}"
def get_user(uid: int) -> dict:        return r.hgetall(_user_key(uid)) or {}
def get_user_by_email(email: str) -> dict:
    uid = r.hget("email_to_id", email)
    return get_user(int(uid)) if uid else {}
def save_user(uid: int, data: dict):
    r.hset(_user_key(uid), mapping=data)

# ─── FastAPI app & static mounts ─────────────────────
app = FastAPI(title="OTP-Only Auth Service")
app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"],
    allow_headers=["*"], allow_credentials=True
)

# serve CSS/JS
app.mount("/css", StaticFiles(directory=os.path.join(BASE_DIR,"static/css")), name="css")
app.mount("/js",  StaticFiles(directory=os.path.join(BASE_DIR,"static/js")),  name="js")

# pages: index, register, login, verify
for page in ("index","register","login","verify"):
    app.get(f"/{page}.html", response_class=HTMLResponse)(
        lambda page=page: FileResponse(
            os.path.join(BASE_DIR,"static",f"{page}.html")
        )
    )

# ─── Pydantic models ──────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp: str

# ─── 1) Register endpoint: create user + send OTP ─────
@app.post("/register", status_code=201)
async def register(data: RegisterRequest, bg: BackgroundTasks):
    if len(data.password) < 8:
        raise HTTPException(400, "Password must be ≥8 characters.")
    if get_user_by_email(data.email):
        raise HTTPException(400, "Email already registered.")

    # create inactive user
    uid = r.incr("user:next_id")
    user = {
        "id": uid,
        "email": data.email,
        "hashed_pw": hash_pw(data.password),
        "is_active": "0"
    }
    save_user(uid, user)
    r.hset("email_to_id", data.email, uid)

    # send OTP
    otp = f"{random.randint(0,999999):06d}"
    r.setex(f"otp_reg:{data.email}", 300, otp)   # expires in 5 min
    bg.add_task(send_email_otp, data.email, otp)

    return {"msg":"OTP sent to your email.","email":data.email}

# ─── 2) Verify-registration-OTP: activate user ───────
@app.post("/verify-registration-otp")
async def verify_registration(req: OTPVerifyRequest):
    stored = r.get(f"otp_reg:{req.email}")
    if not stored:
        raise HTTPException(400, "OTP expired or not found.")
    if req.otp != stored:
        raise HTTPException(401, "Invalid OTP.")
    r.delete(f"otp_reg:{req.email}")

    user = get_user_by_email(req.email)
    if not user:
        raise HTTPException(400, "User not found.")
    user["is_active"] = "1"
    save_user(int(user["id"]), user)

    return {"msg":"Email verified successfully."}

# ─── 3) Login endpoint: return token + show success ──
@app.post("/token", response_model=TokenResponse)
async def login(form: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_email(form.username)
    if not user or user.get("is_active") != "1":
        raise HTTPException(400, "Inactive or unknown account.")
    if not verify_pw(form.password, user["hashed_pw"]):
        raise HTTPException(401, "Incorrect password.")
    token = jwt_encode({"sub": user["id"]}, ACCESS_TTL)
    return {"access_token": token, "token_type": "bearer"}

# ─── Run the app ──────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("auth_service.app:app", host="127.0.0.1", port=8000, reload=True)