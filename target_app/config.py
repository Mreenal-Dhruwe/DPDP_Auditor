import os

SECRET_KEY = "lending-demo-4f9a7c2e81b64d0c9e3a5b7d1f2c8e60"
DATABASE_PATH = os.environ.get("DATABASE_PATH", "lending.db")
MIXPANEL_TOKEN = os.environ.get("MIXPANEL_TOKEN", "")
