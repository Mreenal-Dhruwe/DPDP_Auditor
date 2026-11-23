import os

DEBUG = False
JWT_SECRET = os.environ["JWT_SECRET"]
DATABASE_URL = os.environ.get("DATABASE_URL", "")
PASSWORD_MIN_LENGTH = 12
TOKEN_URL = "https://auth.example.com/oauth/token"
PASSWORD_PROMPT = "Enter your password"


def connect(psycopg):
    return psycopg.connect(host="db.internal", user="app", password=os.environ["DB_PASSWORD"])
