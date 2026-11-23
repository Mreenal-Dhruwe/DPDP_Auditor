import os

DEBUG = False
JWT_SECRET = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"
DATABASE_URL = "postgres://app:Sup3rS3cretPassw0rd@db.internal:5432/app"


def connect(psycopg):
    return psycopg.connect(host="db.internal", user="app", password="Adm1n#2026!")
