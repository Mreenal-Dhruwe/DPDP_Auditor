import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

hourly = TimedRotatingFileHandler("access.log", when="H", backupCount=9000)
by_size = RotatingFileHandler("debug.log", maxBytes=10_000_000, backupCount=3)  # size-based: no days to judge
logging.getLogger().addHandler(hourly)
