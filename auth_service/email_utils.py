import smtplib, ssl
from email.mime.text import MIMEText
from .config import settings

def send_email_otp(to_email: str, otp: str) -> None:
    msg = MIMEText(f"Your one-time password is: {otp}\n\nThis code expires in 5 minutes.")
    msg["Subject"] = "Your OTP code"
    msg["From"]    = settings.EMAIL_FROM
    msg["To"]      = to_email

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as smtp:
            smtp.starttls(context=context)
            smtp.login(settings.SMTP_USER, settings.SMTP_PASS)
            smtp.send_message(msg)
    except smtplib.SMTPAuthenticationError:
        raise RuntimeError(
            "Failed to authenticate with Gmail SMTP. "
            "Did you enable 2FA and create an App Password?"
        )
