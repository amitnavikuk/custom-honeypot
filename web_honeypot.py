# Import library dependencies.
from flask import Flask, render_template, request, redirect, url_for
import logging
from logging.handlers import RotatingFileHandler
from dashboard_data_parser import * 
from pathlib import Path

# Logging Format.
logging_format = logging.Formatter('%(asctime)s %(message)s')

# Define base directory and log file path
base_dir = Path(__file__).parent.parent
log_dir = base_dir / 'mscproject' / 'log_files'

# Ensure the log_files directory exists
log_dir.mkdir(exist_ok=True)

# HTTP Logger log file path
http_audits_log_local_file_path = log_dir / 'http_audit.log'

# HTTP Logger setup
funnel_logger = logging.getLogger('HTTPLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler(http_audits_log_local_file_path, maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

# Baseline Web Honeypot Function
def baseline_web_honeypot(input_username="admin", input_password="deeboodah"):
    app = Flask(__name__)

    # Serve the admin login page
    @app.route('/')
    def index():
        return render_template('wp-admin.html')

    # Handle admin login form submissions
    @app.route('/wp-admin-login', methods=['POST'])
    def login():
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr

        # Log the login attempt
        funnel_logger.info(f'Client with IP Address: {ip_address} entered\nUsername: {username}, Password: {password}')

        # Check for honeytoken interaction
        honeypot_field = request.form.get('honeypot_field', '')
        if honeypot_field:
            funnel_logger.info(f'Honeypot triggered by IP: {ip_address} on login page')

        # Check for decoy credentials
        decoy_username = request.form.get('decoy_username', '')
        decoy_password = request.form.get('decoy_password', '')
        if decoy_username or decoy_password:
            funnel_logger.info(f'Decoy credentials used by IP: {ip_address} with Username: {decoy_username}, Password: {decoy_password}')
        
        # Check credentials
        if username == input_username and password == input_password:
            return 'Please go to https://r.mtdv.me/gYVb1JYxGw'  # This could be changed to a redirect if needed
        else:
            return "Invalid username or password, please try again."

    return app

# Function to run the honeypot application
def run_app(port=5000, input_username="admin", input_password="deeboodah"):
    app = baseline_web_honeypot(input_username, input_password)
    app.run(debug=True, port=port, host="0.0.0.0")
    return app

#run_app()