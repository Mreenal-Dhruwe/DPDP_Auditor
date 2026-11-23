LOGGING = {
    "version": 1,
    "handlers": {
        "file": {
            "class": "logging.handlers.TimedRotatingFileHandler",
            "filename": "app.log",
            "when": "midnight",
            "backupCount": 30,
        },
    },
}
