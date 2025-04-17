import re
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# --- Apache Specific Parsing ---
apache_common_regex = re.compile(  
    r'(?P<ip_address>[^ ]+) - - \[(?P<timestamp>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+) (?P<bytes>\d+)'
)

def parse_apache_log(message: str) -> dict | None:
    match = apache_common_regex.match(message) # Using the common_regex here
    if match:
        log_data = match.groupdict()
        try:
            log_data['timestamp'] = datetime.strptime(log_data['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
             try:
                 log_data['timestamp'] = datetime.strptime(log_data['timestamp'], '%d/%b/%Y:%H:%M:%S')
             except ValueError:
                 logging.warning(f"Apache - Could not parse timestamp: {log_data.get('timestamp')}")
                 log_data['timestamp'] = datetime.now() # Default or handle differently
        try:
            log_data['status'] = int(log_data['status'])
            log_data['bytes'] = int(log_data['bytes']) if log_data['bytes'] != '-' else 0
        except ValueError:
            logging.warning(f"Apache - Could not parse status/bytes: status={log_data.get('status')}, bytes={log_data.get('bytes')}")
            log_data['status'] = 0
            log_data['bytes'] = 0
        return log_data
    return None

# --- Nginx Specific Parsing (Example - Add later) ---
# def parse_nginx_log(message: str) -> dict | None:
#     # Implement Nginx log parsing logic here
#     pass

# --- Main Preprocessing Function ---
def preprocess_log_message(raw_line: str, source_type: str) -> dict | None:
    """
    Parses and preprocesses a raw log line based on its source type.
    """
    processed_data = None
    if source_type == 'apache_access_log':
        processed_data = parse_apache_log(raw_line)
    # elif source_type == 'nginx_access_log':
    #     processed_data = parse_nginx_log(raw_line)
    # elif source_type == 'windows_event':
    #     processed_data = parse_windows_event(raw_line) # Assuming raw_line is structured data/XML

    else:
        logging.warning(f"Unsupported source type for preprocessing: {source_type}")
        return None # Or attempt generic parsing

    if processed_data:
        # --- Add General Preprocessing Steps. ---
        # processed_data['geo_location'] = get_geo_location(processed_data.get('ip_address'))
        pass

    return processed_data