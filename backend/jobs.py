"""In-memory scan jobs run with FastAPI BackgroundTasks (planned for hours 14-24).
Each job unpacks into a temp folder that is deleted in try/finally after the scan;
stored reports expire after REPORT_TTL_DAYS."""
