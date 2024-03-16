from flask import Flask, request, render_template, send_file
import mysql.connector
import requests
import certifi
import os
import subprocess
import time
import json

# Set the REQUESTS_CA_BUNDLE environment variable
os.environ['REQUESTS_CA_BUNDLE'] = certifi.where()

config = {
    'user': 'root',
    'password': '',
    'host': 'localhost',
    'database': 'url',
}

connection = mysql.connector.connect(**config)
app = Flask(__name__)

# Define OWASP ZAP proxy settings
ZAP_PROXY = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# ZAP API base URL
ZAP_API_URL = 'gfpbjfihlmvbvkb1t5pjpe3ddl'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    url1 = request.form['url']
    status = "SCHEDULED"  # Initial status
    timstampData = time.strftime('%Y-%m-%d %H:%M:%S')

    # Insert request into the database
    cursor = connection.cursor()
    cursor.execute(f"INSERT INTO `urltable`(`url`, `status`, `timstampData`) VALUES ('{url1}', '{status}', '{timstampData}')")
    connection.commit()

    return render_template('result.html', url1=url1, status=status)

def execute_penetration_tests():
    while True:
        # Fetch next scheduled request from the database
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM urltable WHERE status='SCHEDULED' ORDER BY timstampData LIMIT 1")
        request_data = cursor.fetchone()

        if request_data:
            url = request_data['url']
            request_id = request_data['id']

            # Update status to IN PROGRESS
            cursor.execute(f"UPDATE urltable SET status='IN PROGRESS' WHERE id={request_id}")
            connection.commit()

            # Execute ZAP penetration test
            zap_report = run_zap(url)

            # Execute Nmap penetration test
            nmap_report = run_nmap(url)

            # Generate combined report
            combined_report = generate_combined_report(zap_report, nmap_report)

            # Save report to a file
            report_filename = f"report_{request_id}.txt"
            with open(report_filename, 'w') as file:
                file.write(combined_report)

            # Update status to COMPLETED and upload the report
            cursor.execute(f"UPDATE urltable SET status='COMPLETED', report='{report_filename}' WHERE id={request_id}")
            connection.commit()

        time.sleep(5)  # Sleep for a while before checking for the next request

def run_zap(url):
    # Start ZAP scan
    scan_url = f"{ZAP_API_URL}/spider/action/scan/?url={url}"
    requests.get(scan_url)

    # Wait for the scan to complete
    time.sleep(30)  # Adjust the sleep time as needed

    # Generate ZAP report
    report_url = f"{ZAP_API_URL}/core/view/alerts"
    zap_report = requests.get(report_url).json()

    return json.dumps(zap_report)

def run_nmap(url):
    # Execute Nmap command
    # Replace the command below with the appropriate Nmap command
    result = subprocess.run(['nmap', '-A', url], capture_output=True, text=True)
    return result.stdout

def generate_combined_report(zap_report, nmap_report):
    # Generate combined report from ZAP and Nmap reports
    # Implement the logic to parse and combine the reports as per user story requirements
    combined_report = f"ZAP Report:\n{zap_report}\n\nNmap Report:\n{nmap_report}"
    return combined_report

@app.route('/download/<int:request_id>')
def download_report(request_id):
    cursor = connection.cursor(dictionary=True)
    cursor.execute(f"SELECT report FROM urltable WHERE id={request_id}")
    report_filename = cursor.fetchone()['report']
    return send_file(report_filename, as_attachment=True)

if __name__ == '__main__':
    # Start a separate thread to continuously execute penetration tests
    import threading
    t = threading.Thread(target=execute_penetration_tests)
    t.start()

    app.run(debug=True)
