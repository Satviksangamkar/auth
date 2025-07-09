import os
import time
from dotenv import load_dotenv
from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, Form
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
import redis
from passlib.context import CryptContext
from jose import jwt
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig


# Load environment variables
load_dotenv()
BASE_URL = os.getenv("BASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET")
TOKEN_TTL = int(os.getenv("TOKEN_TTL", 3600))
ACCESS_TTL = int(os.getenv("ACCESS_TTL", 3600))

# Redis setup
r = redis.Redis(
    host=os.getenv("REDIS_HOST"),
    port=int(os.getenv("REDIS_PORT")),
    password=os.getenv("REDIS_PASSWORD"),
    decode_responses=True
)

# Password and JWT utilities
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="token")

def hash_pw(pw: str) -> str:
    return pwd_ctx.hash(pw)

def verify_pw(pw: str, hpw: str) -> bool:
    return pwd_ctx.verify(pw, hpw)

def jwt_encode(data: dict, ttl: int) -> str:
    payload = {**data, "exp": time.time() + ttl}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def jwt_decode(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except:
        return {}

# Mail setup
mail_conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("SMTP_USER"),
    MAIL_PASSWORD=os.getenv("SMTP_PASS"),
    MAIL_FROM=os.getenv("SMTP_USER"),
    MAIL_PORT=int(os.getenv("SMTP_PORT")),
    MAIL_SERVER=os.getenv("SMTP_HOST"),
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
    TEMPLATE_FOLDER="templates/email"
)
fast_mail = FastMail(mail_conf)

async def send_verification_email(email: str, token: str):
    link = f"{BASE_URL}/confirm_email?token={token}"
    message = MessageSchema(
        subject="Confirm your account",
        recipients=[email],
        template_body={"link": link},
        subtype="html"
    )
    await fast_mail.send_message(message, template_name="verify.html")

# Pydantic Models
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

class EmailRequest(BaseModel):
    email: EmailStr

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

# FastAPI App
app = FastAPI(title="FastAPI Auth with Email Verification")

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helpers for Redis keys
def user_key(uid: int) -> str:
    return f"user:{uid}"

def email_to_id_key() -> str:
    return "email_to_id"

def token_key(token: str) -> str:
    return f"verify_token:{token}"

# Serve HTML pages via explicit GET handlers
@app.get("/register.html", response_class=HTMLResponse)
def get_register():
    return FileResponse("static/register.html")

@app.get("/login.html", response_class=HTMLResponse)
def get_login():
    return FileResponse("static/login.html")

@app.get("/confirm.html", response_class=HTMLResponse)
def get_confirm():
    return FileResponse("static/confirm.html")

@app.get("/invalid.html", response_class=HTMLResponse)
def get_invalid():
    return FileResponse("static/invalid.html")

# Mount static files
app.mount("/css", StaticFiles(directory="static/css"), name="css")
app.mount("/js", StaticFiles(directory="static/js"), name="js")

# Routes
@app.post("/register", status_code=201)
async def register(req: RegisterRequest, bg: BackgroundTasks):
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be ≥8 characters.")
    if r.hget(email_to_id_key(), req.email):
        raise HTTPException(400, "Email already registered.")
    uid = r.incr("user:next_id")
    r.hset(user_key(uid), mapping={
        "id": uid,
        "email": req.email,
        "hashed_pw": hash_pw(req.password),
        "is_active": "0"
    })
    r.hset(email_to_id_key(), req.email, uid)
    token = jwt_encode({"sub": uid}, TOKEN_TTL)
    r.setex(token_key(token), TOKEN_TTL, uid)
    bg.add_task(send_verification_email, req.email, token)
    return {"msg": "Registered! Check your mailbox to verify."}

@app.get("/confirm_email")
def confirm_email(token: str):
    uid = r.get(token_key(token))
    if not uid:
        return FileResponse("static/invalid.html")
    r.hset(user_key(uid), "is_active", "1")
    r.delete(token_key(token))
    return FileResponse("static/confirm.html")

@app.post("/resend_verification")
async def resend_verification(req: EmailRequest, bg: BackgroundTasks):
    uid = r.hget(email_to_id_key(), req.email)
    user = r.hgetall(user_key(uid or 0))
    if not user or user.get("is_active") == "1":
        raise HTTPException(400, "No pending account for this email.")
    count = int(r.get(f"resend:{req.email}") or 0)
    if count >= 3:
        raise HTTPException(429, "Resend limit reached. Try again later.")
    r.incr(f"resend:{req.email}")
    r.expire(f"resend:{req.email}", 3600)
    token = jwt_encode({"sub": uid}, TOKEN_TTL)
    r.setex(token_key(token), TOKEN_TTL, uid)
    bg.add_task(send_verification_email, req.email, token)
    return {"msg": "Verification email resent."}

@app.post("/token", response_model=TokenResponse)
def login(form: OAuth2PasswordRequestForm = Depends()):
    uid = r.hget(email_to_id_key(), form.username)
    user = r.hgetall(user_key(int(uid or 0)))
    if not user or user.get("is_active") != "1":
        raise HTTPException(400, "Inactive or unknown account.")
    if not verify_pw(form.password, user["hashed_pw"]):
        raise HTTPException(401, "Incorrect password.")
    access = jwt_encode({"sub": user["id"]}, ACCESS_TTL)
    return {"access_token": access, "token_type": "bearer"}

@app.get("/", response_class=HTMLResponse)
def index():
    return FileResponse("static/register.html")

# Run the app
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
