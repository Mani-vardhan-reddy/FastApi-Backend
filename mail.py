from fastapi_mail import FastMail, ConnectionConfig, MessageSchema,MessageType
from config import settings
from pathlib import Path
import ssl
import certifi
import aiosmtplib

original_connect = aiosmtplib.SMTP.connect

async def patched_connect(self, *args, **kwargs):
    if "tls_context" not in kwargs:
        kwargs["tls_context"] = ssl.create_default_context(cafile=certifi.where())
    return await original_connect(self, *args, **kwargs)

aiosmtplib.SMTP.connect = patched_connect

ssl_context = ssl.create_default_context(cafile=certifi.where())

BASE_DIR = Path(__file__).resolve().parent

config = ConnectionConfig(
    MAIL_USERNAME = settings.MAIL_USERNAME,
    MAIL_PASSWORD = settings.MAIL_PASSWORD,
    MAIL_FROM = settings.MAIL_FROM,
    MAIL_PORT = settings.MAIL_PORT,
    MAIL_SERVER = settings.MAIL_SERVER,
    MAIL_FROM_NAME = settings.MAIL_FROM_NAME,
    MAIL_STARTTLS= True ,
    MAIL_SSL_TLS = False,
    USE_CREDENTIALS = True,
    VALIDATE_CERTS = False,
    TEMPLATE_FOLDER= Path(BASE_DIR, "template")
    
)

mail = FastMail(config= config)

def create_message(recipients:list[str],subject:str,body:str):
    message = MessageSchema(recipients=recipients,subject=subject,body=body , subtype=MessageType.html)
    return message