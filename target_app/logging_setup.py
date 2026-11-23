# Log files for the demo lending app. Answer key: ../ground_truth.yml
# One file per day, kept for 400 days: DPDP Rule 8(3) asks for at least a year.
import logging
from logging.handlers import TimedRotatingFileHandler


def setup_logging(path="logs/lending.log"):
    handler = TimedRotatingFileHandler(path, when="midnight", backupCount=400)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)
