#!/usr/bin/env python3
# wazuh_yara_to_graylog.py - Script to forward Wazuh YARA logs to Graylog via Raw/TCP

import json
import time
import logging
import socket
import re
import os
import sys
import argparse
from datetime import datetime

# Configure argument parser
parser = argparse.ArgumentParser(description='Forward Wazuh YARA logs to Graylog via Raw TCP')
parser.add_argument('--wazuh-log', default='/var/ossec/logs/alerts/alerts.json', help='Path to Wazuh alerts.json file')
parser.add_argument('--graylog-host', required=True, help='Graylog server hostname or IP')
parser.add_argument('--graylog-port', type=int, default=5140, help='Graylog Raw TCP input port')
parser.add_argument('--filter-rule', default='108001', help='Wazuh rule ID to filter')
parser.add_argument('--interval', type=int, default=0.1, help='Polling interval in seconds')
parser.add_argument('--debug', action='store_true', help='Enable debug logging')
parser.add_argument('--tcp-timeout', type=int, default=5, help='TCP connection timeout in seconds')
args = parser.parse_args()

# Configure logging
log_level = logging.DEBUG if args.debug else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('wazuh-yara-to-graylog')

# Get hostname
hostname = socket.gethostname()

def parse_yara_log(log_data):
    """Parse the YARA log from Wazuh alerts.json format and convert to JSON."""
    try:
        # Parse rule ID to match filter
        rule_id = log_data.get('rule', {}).get('id')
        if rule_id != args.filter_rule:
            return None

        # Extract timestamp
        timestamp = log_data.get('timestamp', datetime.now().isoformat())

        # Get YARA data
        yara_data = log_data.get('data', {}).get('YARA', {})
        if not yara_data and 'full_log' in log_data:
            # Try to extract from full_log if YARA data not structured
            full_log = log_data.get('full_log', '')
            match = re.search(r'wazuh-YARA: (\w+) - Scan result: (.?) \[(.?)\] (.?) \| chatgpt_response: (.)', full_log)
            if match:
                log_type, rule_name, rule_attrs, scanned_file, chatgpt_response = match.groups()
                # Extract description from attributes
                desc_match = re.search(r'description="([^"]+)"', rule_attrs)
                rule_description = desc_match.group(1) if desc_match else ""
                # Extract date from attributes
                date_match = re.search(r'date="([^"]+)"', rule_attrs)
                published_date = date_match.group(1) if date_match else ""

                yara_data = {
                    'log_type': log_type,
                    'rule_name': rule_name,
                    'rule_description': rule_description,
                    'published_date': published_date,
                    'scanned_file': scanned_file,
                    'chatgpt_response': chatgpt_response
                }

        # Get agent data
        agent = log_data.get('agent', {})
        agent_name = agent.get('name', 'unknown')
        agent_ip = agent.get('ip', '0.0.0.0')

        # Get Wazuh manager name
        manager_name = log_data.get('manager', {}).get('name', 'unknown')

        # Create JSON-formatted message
        json_message = {
            'timestamp': timestamp,
            'host': hostname,
            'rule_id': rule_id,
            'rule_description': log_data.get('rule', {}).get('description', ''),
            'agent_name': agent_name,
            'agent_ip': agent_ip,
            'manager': manager_name,
            'yara_rule': yara_data.get('rule_name', ''),
            'yara_description': yara_data.get('rule_description', ''),
            'scanned_file': yara_data.get('scanned_file', ''),
            'chatgpt_response': yara_data.get('chatgpt_response', '')
        }

        return json.dumps(json_message)
    except Exception as e:
        logger.error(f"Error parsing log: {str(e)}")
        if args.debug:
            logger.exception("Detailed error:")
        return None

def send_to_graylog_tcp(message):
    """Send JSON-formatted message to Graylog via Raw TCP."""
    try:
        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(args.tcp_timeout)

        # Connect to Graylog
        sock.connect((args.graylog_host, args.graylog_port))

        # Add newline to message if not present
        if not message.endswith('\n'):
            message += '\n'

        # Send message
        sock.sendall(message.encode('utf-8'))

        # Close socket
        sock.close()

        logger.debug(f"Sent message to Graylog via TCP: {message[:100]}...")
        return True
    except socket.timeout:
        logger.error(f"Timeout connecting to Graylog at {args.graylog_host}:{args.graylog_port}")
        return False
    except ConnectionRefusedError:
        logger.error(f"Connection refused to Graylog at {args.graylog_host}:{args.graylog_port}")
        return False
    except Exception as e:
        logger.error(f"Error sending to Graylog via TCP: {str(e)}")
        if args.debug:
            logger.exception("Detailed error:")
        return False

def tail_file(filename):
    """Generator to tail a file similar to 'tail -f'."""
    with open(filename, 'r') as f:
        # Go to the end of the file
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

def main():
    """Main function to monitor Wazuh logs and forward to Graylog."""
    logger.info(f"Starting  YARA to Graylog forwarder (Raw TCP)")
    logger.info(f"Monitoring file: {args.wazuh_log}")
    logger.info(f"Forwarding to Graylog at {args.graylog_host}:{args.graylog_port} via Raw TCP")

    # Track connection status to avoid repeated error messages
    connection_status = True

    try:
        # Check if log file exists
        if not os.path.exists(args.wazuh_log):
            logger.error(f"Log file not found: {args.wazuh_log}")
            sys.exit(1)

        for line in tail_file(args.wazuh_log):
            try:
                # Parse JSON log
                log_data = json.loads(line)

                # Parse YARA log
                formatted_message = parse_yara_log(log_data)
                if not formatted_message:
                    continue

                # Send to Graylog
                success = send_to_graylog_tcp(formatted_message)

                if success:
                    if not connection_status:
                        logger.info("Reconnected to Graylog successfully")
                        connection_status = True
                    logger.info(f"Forwarded YARA match to Graylog")
                    if args.debug:
                        logger.debug(f"Message: {formatted_message}")
                else:
                    connection_status = False

                # Sleep to avoid consuming too many resources
                time.sleep(args.interval)

            except json.JSONDecodeError:
                # Skip non-JSON lines
                continue
            except Exception as e:
                logger.error(f"Error processing log line: {str(e)}")
                if args.debug:
                    logger.exception("Detailed error:")
                continue
    except KeyboardInterrupt:
        logger.info("Stopping  YARA to Graylog forwarder")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Critical error: {str(e)}")
        if args.debug:
            logger.exception("Detailed error:")
        sys.exit(1)

if _name_ == "_main_":
    main()
