from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
import socket
from urllib.parse import urlparse
import nmap
import time
from zapv2 import ZAPv2
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from queue import Queue
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a more secure secret key

# MySQL configuration
db_config = {
    'user': 'root',
    'password': '',
    'host': 'localhost',
    'database': 'url',
}

# Function to connect to MySQL database
def connect_to_database():
    try:
        connection = mysql.connector.connect(**db_config)
        return connection
    except mysql.connector.Error as error:
        print("Error while connecting to MySQL database:", error)
        return None

# Route for home page
@app.route('/')
def home():
    if 'username' in session:
        return render_template('login.html', username=session['username'])
    else:
        return redirect(url_for('login'))

# Route for signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        connection = connect_to_database()
        if connection:
            cursor = connection.cursor()
            cursor.execute("INSERT INTO user (username, email, password) VALUES (%s, %s, %s)", (username, email, password))
            connection.commit()
            cursor.close()
            connection.close()
            return redirect(url_for('login'))
        else:
            return "Failed to connect to the database."
    return render_template('signup.html')

# Route for login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        connection = connect_to_database()
        if connection:
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM user WHERE username = %s AND password = %s", (username, password))
            user = cursor.fetchone()
            cursor.close()
            connection.close()
            if user:
                session['username'] = user[1]
                return render_template('urlpage.html', username=username)
            else:
                return "Invalid username or password."
        else:
            return "Failed to connect to the database."
    return render_template('login.html')

# Route for processing URL
@app.route('/processurl', methods=['POST'])
def process_url():
    data = request.json.get('data')
    global url
    url = data.strip()
    
    if url:
        connection = connect_to_database()
        if connection:
            try:
                cursor = connection.cursor()
                cursor.execute("INSERT INTO urltable (url, status, timstampData) VALUES (%s, %s, %s)", (url, 'SCHEDULED', time.strftime('%Y-%m-%d %H:%M:%S')))
                connection.commit()
                cursor.close()
                connection.close()
            except mysql.connector.Error as error:
                print("Error inserting URL into database:", error)
                return "Error inserting URL into database."
            else:
                ip_address = url_to_ip(url)
                if ip_address:
                    print(f"The IP address of {url} is {ip_address}")
                    nm = nmap.PortScanner()
                    nm.scan(ip_address, '22-443')
                    generate_port_report(ip_address, nm)
                    
                    apiKey = 'gfpbjfihlmvbvkb1t5pjpe3ddl'
                    zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
                    
                    print('Starting Web Application Vulnerability Scan...')
                    scanID = zap.ascan.scan(url)
                    while True:
                        status = zap.ascan.status(scanID)
                        if status == '100':
                            print('Web Application Vulnerability Scan completed')
                            alerts = zap.core.alerts(baseurl=url)
                            generate_vulnerability_report(url, alerts)
                            break
                        else:
                            print('Scan status: {}'.format(status))
                            time.sleep(5)
                else:
                    print(f"Failed to resolve the IP address of {url}")
                    return "Failed to resolve the IP address of the URL."
    else:
        print("Empty URL received")
        return "Empty URL received."
    return "URL processed successfully."

def url_to_ip(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        return None
def generate_port_report(ip_address, nm):
    global table_data  # Declare table_data as global
    table_data = [['Port Number', 'Protocol', 'Services', 'Recommended Action']]

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = list(nm[host][proto].keys())
            lport.sort()
            for port in lport:
                port_number = port
                protocol = proto
                services = nm[host][proto][port]['name']
                recommended_action = "Update firewall rules or apply security patches"
                table_data.append([port_number, protocol, services, recommended_action])
                
from reportlab.pdfgen import canvas
def generate_vulnerability_report(target, alerts):
    global table_data  # Access table_data as global
    pdf_file = f"final_report{url}.pdf"
    print(url)
    c = canvas.Canvas(pdf_file, pagesize=letter)
    c.setFont("Helvetica", 12)

    total_vulnerabilities = len(alerts)
    vulnerabilities_grouped = {}
    for alert in alerts:
        risk_rating = alert.get('risk')
        if risk_rating in vulnerabilities_grouped:
            vulnerabilities_grouped[risk_rating] += 1
        else:
            vulnerabilities_grouped[risk_rating] = 1

    c.drawString(100, 750, 'Summary:')
    c.drawString(100, 730, 'i. No. of Total Vulnerabilities Identified: {}'.format(total_vulnerabilities))
    c.drawString(100, 710, 'ii. No. of Total Vulnerabilities Identified grouped on Risk Rating:')
    y_pos = 690
    for rating, count in vulnerabilities_grouped.items():
        c.drawString(120, y_pos, '- {}: {}'.format(rating, count))
        y_pos -= 20

    c.drawString(100, 670, '\nDetailed Report:')
    y_pos -= 50
    t = Table(table_data)
    t.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                           ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                           ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                           ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                           ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                           ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                           ('GRID', (0, 0), (-1, -1), 1, colors.black)]))
    t.wrapOn(c, 200, 400)
    t.drawOn(c, 100, 650)
    for alert in alerts:
        c.drawString(120, y_pos, 'i. Vulnerability Summary: {}'.format(alert.get('alert')))
        c.drawString(120, y_pos-20, 'ii. Risk Rating: {}'.format(alert.get('risk')))
        c.drawString(120, y_pos-40, 'iii. Confidence Rating: {}'.format(alert.get('confidence')))
        c.drawString(120, y_pos-60, 'iv. Description: {}'.format(alert.get('description')))
        instances = alert.get('instances')
        if instances is not None and len(instances) > 0:
            c.drawString(120, y_pos-80, 'v. Details to Reproduce the Instance: {}'.format(instances[0].get('uri')))
        else:
            c.drawString(120, y_pos-80, 'v. Details to Reproduce the Instance: No instances found for the alert.')
        y_pos -= 120

    c.save()
    print("Vulnerability report generated successfully: {}".format(pdf_file))
    






if __name__ == '__main__':
    app.run(debug=True)
