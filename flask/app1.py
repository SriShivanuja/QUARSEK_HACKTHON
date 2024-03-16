from flask import Flask, request, render_template, send_file
import mysql.connector
import requests
import certifi
import os
import subprocess
import time
import json
import socket
from urllib.parse import urlparse
import time
from zapv2 import ZAPv2


config = {
    'user': 'root',
    'password': '',
    'host': 'localhost',
    'database': 'url',
}

connection = mysql.connector.connect(**config)
app = Flask(__name__)

# Define OWASP ZAP proxy settings

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    url1 = request.form['url']
    status = "SCHEDULED"  # Initial status
    timstampData = time.strftime('%Y-%m-%d %H:%M:%S')
    id=0
    print(url1)
    print(status)

    # Insert request into the database
    
    cursor = connection.cursor()
    cursor.execute(f"INSERT INTO `urltable`(`id`,`url`, `status`, `timstampData`) VALUES ('{id}','{url1}', '{status}', '{timstampData}')")
    connection.commit()
    
    return render_template('index.html', url1=url1, status=status)

# def execute_penetration_tests():
#     while True:
#         print("okkokoko")
#         # Fetch next scheduled request from the database
#         cursor = connection.cursor(dictionary=True)
#         cursor.execute("SELECT * FROM urltable WHERE status='SCHEDULED' ORDER BY timstampData LIMIT 1")
#         request_data = cursor.fetchone()

#         if request_data:
#             url = request_data['url']
#             request_id = request_data['id']

#             # Update status to IN PROGRESS
#             cursor.execute(f"UPDATE urltable SET status='IN PROGRESS' WHERE id={request_id}")
#             connection.commit()

#             # Execute ZAP and Nmap penetration tests
#             zap_report = run_zap(url)
#             nmap_report = run_nmap(url)

#             # Generate combined report
#             combined_report = generate_combined_report(zap_report, nmap_report)

#             # Save report to a file
#             report_filename = f"report_{request_id}.txt"
#             with open(report_filename, 'w') as file:
#                 file.write(combined_report)

#             # Update status to COMPLETED and upload the report
#             cursor.execute(f"UPDATE urltable SET status='COMPLETED', report='{report_filename}' WHERE id={request_id}")
#             connection.commit()

#         time.sleep(5)  # Sleep for a while before checking for the next request

def run_zap(url):
    # The URL of the application to be tested
    
# Change to match the API key set in ZAP, or use None if the API key is disabled
    apiKey = 'gfpbjfihlmvbvkb1t5pjpe3ddl'

# By default ZAP API client will connect to port 8080
    zap = ZAPv2(apikey=apiKey)
# Use the line below if ZAP is not listening on port 8080, for example, if listening on port 8090
# zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})

# Ajax Spider
    print('Ajax Spider target {}'.format(url))
    scanID = zap.ajaxSpider.scan(url)

    timeout = time.time() + 60*2   # 2 minutes from now
# Loop until the ajax spider has finished or the timeout has exceeded
    while zap.ajaxSpider.status == 'running':
        if time.time() > timeout:
            break
        print('Ajax Spider status: ' + zap.ajaxSpider.status)
        time.sleep(2)

    print('Ajax Spider completed')

# Active Scan
    print('Active Scanning target {}'.format(url))
    scanID = zap.ascan.scan(url)

# Check if scanID is valid
    if scanID and scanID != '0':
        print('Active Scan initiated successfully. Scan ID:', scanID)
    else:
        print("Failed to start the active scan or scan does not exist.")

# Wait for the active scan to complete
    timeout = time.time() + 60*10  # 10 minutes from now
    while True:
        scan_status = zap.ascan.status(scanID)
        print('Active Scan progress %:', scan_status)

        if scan_status == '100':
            break

        if time.time() > timeout:
            print("Timeout reached. Active scan did not complete within the specified time.")
            break

        time.sleep(5)
# Print detailed re
# port for ports
# Fetching detailed report for ports
    print("\nDetailed Report for Ports:")
    arr=zap.core.alerts(baseurl=url)
    num_of_alert = zap.core.number_of_alerts(baseurl=url)
    print(num_of_alert)
    print('Active Scan completed')


def url_to_ip(url):
    try:
        # Parse the URL to extract the hostname
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        # Get the IP address corresponding to the hostname
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        # Handle the case where the hostname cannot be resolved to an IP address
        return None

def run_nmap(url):
# Example usage
    ip_address = url_to_ip(url)
    if ip_address:
        print(f"The IP address of {url} is {ip_address}")
    else:
        print(f"Failed to resolve the IP address of {url}")
    import nmap
    nm = nmap.PortScanner()
    nm.scan(ip_address, '22-443')
    print(nm.command_line())
    print(nm.scaninfo())
    print(nm.all_hosts())
    [ip_address]
    print(nm[ip_address].hostname())
    print(nm[ip_address].state())
    print(nm[ip_address].all_protocols())
    print(nm[ip_address]['tcp'].keys())
    print(nm[ip_address].has_tcp(22))

    print(nm[ip_address].has_tcp(23))

    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
            lport = list(nm[ip_address]['tcp'].keys())
            lport.sort()
            for port in lport:
                print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))



# def generate_combined_report(zap_report, nmap_report):
#     # Generate combined report from ZAP and Nmap reports
#     # Implement the logic to parse and combine the reports as per user story requirements
#     combined_report = f"ZAP Report:\n{zap_report}\n\nNmap Report:\n{nmap_report}"
#     return combined_report

# @app.route('/download/<int:request_id>')
# def download_report(request_id):
#     cursor = connection.cursor(dictionary=True)
#     cursor.execute(f"SELECT report FROM urltable WHERE id={request_id}")
#     report_filename = cursor.fetchone()['report']
#     return send_file(report_filename, as_attachment=True)

if __name__ == '__main__':
  
    app.run(debug=True)
