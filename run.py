"""
This script is designed to automate the process of checking SSL certificates
for specified services across a network of servers.

It validates the certificates to ensure they are valid, recently issued,
and not nearing expiration.

If a certificate is found to be expiring, expired, or if there are any connection issues,
the script notifies the engineering team via Slack.

Additionally, it updates metrics on a statsd serverto record the status of
certificates for each service.

The script supports running in a verbose mode for detailed logging and
utilizes threading to efficiently check multiple servers concurrently.

It ensures input validation and sanitization to prevent injection attacks and
employs robust error handling and logging mechanisms for reliable operation.

Usage:
    python run.py [-v | --verbose]

Options:
    -v, --verbose    Enable verbose (debug) logging to provide detailed information
                     about the script's operation and any issues encountered.
"""
import subprocess
import logging
import concurrent.futures
import argparse
import re

from datetime import datetime
from ipaddress import ip_address
from statsd import StatsClient

import requests


# Set up command line argument parsing for verbosity
parser = argparse.ArgumentParser(description='Check SSL certificates and notify via Slack.')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose (debug) logging')
args = parser.parse_args()

# Configure logging
logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for service ports, statsd server address and port,
# Slack webhook URL, and IP addresses file.
EUROPA_PORT = 4000
CALLISTO_PORT = 8000
STATSD_ADDRESS = '10.10.4.14'
STATSD_PORT = 8125
SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'
IP_ADDRESSES_FILE = 'takehome_ip_addresses.txt'

# Initialize StatsD client for sending metrics
statsd_client = StatsClient(host=STATSD_ADDRESS, port=STATSD_PORT)

def is_valid_ip(ip):
    """
    Validates if the provided string is a valid IP address.

    :param ip: The IP address as a string.
    :return: True if the IP address is valid, False otherwise.
    """
    try:
        ip_address(ip)  # This will throw an error if the IP is not valid
        return True
    except ValueError:
        return False

def is_valid_port(port):
    """
    Validates if the provided port number is within the valid range of 0-65535.

    :param port: The port number as an integer.
    :return: True if the port is valid, False otherwise.
    """
    return 0 <= port <= 65535

def sanitize_input(input_string):
    """
    Sanitizes the input string by escaping potentially dangerous characters.

    This is a basic example; depending on context, you might need a more thorough approach.

    :param input_string: The input string to sanitize.
    :return: The sanitized string.
    """
    return re.sub(r'[^a-zA-Z0-9.-]', '', input_string)

def check_ssl_certificate(ip, port):
    """
    Checks the SSL certificate of a given IP and port using OpenSSL.
    Parses the certificate's not before and not after dates to determine its status.

    :param ip: The IP address of the server.
    :param port: The port on which the server is running.
    :return: A string indicating the certificate status
             ('valid', 'expired', 'expiring', or 'connection_error').
    """
    # Validate IP and port
    if not is_valid_ip(ip) or not is_valid_port(port):
        logging.error("Invalid IP address or port")
        return 'invalid_input'

    # Sanitize inputs (if used in a way that could be risky, which generally should be avoided)
    safe_ip = sanitize_input(ip)
    safe_port = sanitize_input(str(port))

    try:
        # Construct and execute the OpenSSL command to retrieve certificate validity dates
        command = f'echo | openssl s_client -connect {safe_ip}:{safe_port} 2>/dev/null | openssl x509 -noout -dates'
        logging.debug(command)
        output = subprocess.check_output(command, shell=True).decode('utf-8')
        logging.debug(f"OpenSSL output for {safe_ip}:{safe_port}: {output}")

        not_before, not_after = None, None
        for line in output.splitlines():
            if 'notBefore' in line:
                not_before = datetime.strptime(line.split('=')[1], "%b %d %H:%M:%S %Y GMT")
            elif 'notAfter' in line:
                not_after = datetime.strptime(line.split('=')[1], "%b %d %H:%M:%S %Y GMT")

        if not_before and not_after:
            now = datetime.utcnow()
            if now < not_before:
                return 'not_valid_yet'
            elif now > not_after:
                return 'expired'
            elif (not_after - now).days <= 30:
                return 'expiring'
            else:
                return 'valid'
    except subprocess.CalledProcessError:
        logging.error(f"Failed to connect to {safe_ip}:{safe_port} to check SSL certificate.")
        return 'connection_error'

def send_slack_notification(message):
    """
    Sends a message to a Slack channel using a webhook URL.

    :param message: The message to be sent to Slack.
    :return: True if the message was successfully sent, False otherwise.
    """
    payload = {"text": message}
    timeout_seconds = 10
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=timeout_seconds)
        if response.status_code == 200:
            logging.info(f"Notification sent to Slack: {message}")
        else:
            logging.error(f"Failed to send notification to Slack. Status Code: {response.status_code}")
        return response.status_code == 200
    except requests.exceptions.Timeout:
        logging.error("The request to Slack timed out.")
        return False

def update_statsd_metric(metric_name):
    """
    Updates a given metric in StatsD by incrementing its value.

    :param metric_name: The name of the metric to be updated.
    """
    statsd_client.gauge(metric_name, 1, delta=True)
    logging.debug(f"Updated StatsD metric: {metric_name}")

def check_ssl_certificate_for_service(ip_service_tuple):
    """
    Wrapper function to check SSL certificate for a given IP and service.
    This function is designed to be compatible with threading/multiprocessing.

    :param ip_service_tuple: A tuple containing the IP address and the service name.
    """
    ip, service_name = ip_service_tuple
    port = EUROPA_PORT if service_name == 'Europa' else CALLISTO_PORT

    status = check_ssl_certificate(ip, port)
    message = f"{service_name} service at {ip}:{port} is {status}."

    # Define a mapping of statuses to their corresponding urgency messages and metric suffixes
    status_mapping = {
        'expired': ('URGENT: ', 'expired'),
        'expiring': ('WARNING: ', 'expiring'),
        'not_valid_yet': ('ERROR: ', 'outdated'),
        'connection_error': ('ERROR: ', 'outdated'),
    }

    # Use the status to look up the corresponding urgency message and metric suffix
    urgency_message, metric_suffix = status_mapping.get(status, ('', ''))

    if status in status_mapping:
        # Prepend the urgency message to the original message
        full_message = urgency_message + message
        send_slack_notification(full_message)
        update_statsd_metric(f'certs.{service_name.lower()}.{metric_suffix}')

    logging.info(f"Processed SSL certificate check for {service_name} at {ip}:{port}: {status}")

def main():
    """
    Main function modified to use threading for concurrent SSL certificate checks.
    """
    ip_service_pairs = []
    with open(IP_ADDRESSES_FILE, 'r', encoding='utf-8') as file:
        for line in file:
            ip_service_pairs.append(line.strip().split(','))

    # Use ThreadPoolExecutor to check certificates in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(check_ssl_certificate_for_service, ip_service_pairs)

if __name__ == "__main__":
    main()
