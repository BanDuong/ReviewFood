import datetime
import jwt
from django.conf import settings


def generate_access_token(user):
    access_payload = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_admin": user.is_admin,
        "is_superuser": user.is_superuser,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=5),
        "iat": datetime.datetime.utcnow(),
    }
    access_token = jwt.encode(access_payload, settings.SECRET_KEY, algorithm='HS256')

    return access_token

def generate_fresh_token(user):
    fresh_payload = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_admin": user.is_admin,
        "is_superuser": user.is_superuser,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
        "iat": datetime.datetime.utcnow(),
    }
    refresh_token = jwt.encode(fresh_payload, settings.REFRESH_KEY, algorithm='HS256')

    return refresh_token

def generate_ID_token(user):
    pass
