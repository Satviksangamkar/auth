from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
import random


# ⬇️  relative imports
from ..email_utils import send_email_otp
from ..redis_client import r

router = APIRouter(prefix="/otp", tags=["otp"])

class EmailRequest(BaseModel):
    email: EmailStr

class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp: str

@router.post("/send")
async def send_otp(req: EmailRequest):
    otp = str(random.randint(100_000, 999_999))
    r.setex(f"otp:{req.email}", 300, otp)           # 5-minute expiry
    send_email_otp(req.email, otp)
    return {"msg": "OTP sent to e-mail"}

@router.post("/verify")
async def verify_otp(req: OTPVerifyRequest):
    stored = r.get(f"otp:{req.email}")
    if not stored:
        raise HTTPException(400, "OTP expired or not found")
    if req.otp != stored:
        raise HTTPException(401, "Invalid OTP")
    r.delete(f"otp:{req.email}")                    # optional cleanup
    return {"msg": "E-mail verified successfully"}
