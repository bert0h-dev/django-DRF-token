from django.core import signing
from django.conf import settings

# Tiempo de expiración en segundos (ej. 24 horas)
TOKEN_EXPIRE_SECONDS = 60 * 60 * 24

# Salt personalizado para diferenciar del uso de otros tokens
EMAIL_VERIFICATION_SALT = "email-confirmation"
PASSWORD_RESET_SALT = "password-reset"

def generate_email_token(user):
    return signing.dumps({"user_id": user.id}, salt=EMAIL_VERIFICATION_SALT)

def verify_email_token(token):
    try:
        data = signing.loads(token, salt=EMAIL_VERIFICATION_SALT, max_age=TOKEN_EXPIRE_SECONDS)
        return data.get("user_id")
    except signing.SignatureExpired:
        return None  # Token expirado
    except signing.BadSignature:
        return None  # Token alterado o inválido
    
def generate_password_reset_token(user):
    return signing.dumps({"user_id": user.id}, salt=PASSWORD_RESET_SALT)

def verify_password_reset_token(token):
    try:
        data = signing.loads(token, salt=PASSWORD_RESET_SALT, max_age=TOKEN_EXPIRE_SECONDS)
        return data.get("user_id")
    except signing.SignatureExpired:
        return None
    except signing.BadSignature:
        return None