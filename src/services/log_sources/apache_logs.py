# app/services/log_sources/apache_logs.py
import os
import time
import logging
from src.core.config import settings
from src.services.ai_ml.ingestion import process_raw_log_line

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

APACHE_ACCESS_LOG_PATH = settings.APACHE_ACCESS_LOG_PATH
LOG_READ_INTERVAL_SEC = 1

def follow_apache_logs():
    """Continuously reads new lines from the Apache log file and sends them for ingestion."""
    logging.info(f"Starting Apache log follower for file: {APACHE_ACCESS_LOG_PATH}")
    last_inode = None
    last_pos = 0

    while True:
        try:
            # Check if file exists before attempting to open
            if not os.path.exists(APACHE_ACCESS_LOG_PATH):
                logging.warning(f"Log file not found: {APACHE_ACCESS_LOG_PATH}. Waiting...")
                time.sleep(LOG_READ_INTERVAL_SEC * 5) # Wait longer if file not found
                continue

            current_inode = os.stat(APACHE_ACCESS_LOG_PATH).st_ino
            with open(APACHE_ACCESS_LOG_PATH, 'r') as logfile:
                if last_inode is not None and current_inode != last_inode:
                    logging.info("Log file rotated. Resetting position.")
                    last_pos = 0
                last_inode = current_inode

                logfile.seek(last_pos)
                lines = logfile.readlines()
                last_pos = logfile.tell()

                if lines:
                    for line in lines:
                        line = line.strip()
                        if line:
                            # Send the raw line to the ingestion service
                            process_raw_log_line(line, source_type='apache_access_log') # Pass source_type
                            pass

        except FileNotFoundError:
             # Handled by the check above, but keep for safety
             logging.error(f"Log file disappeared: {APACHE_ACCESS_LOG_PATH}. Retrying...")
        except Exception as e:
            logging.error(f"An error occurred reading Apache logs: {e}")

        time.sleep(LOG_READ_INTERVAL_SEC)

if __name__ == "__main__":
    follow_apache_logs()