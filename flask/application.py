from flask import Flask, render_template, request, redirect, url_for, session,jsonify
import mysql.connector
import socket
from urllib.parse import urlparse
import nmap
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle

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
            cursor.execute(f"INSERT INTO user (username,email, password) VALUES ('{username}','{email}', '{password}')")
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
        print(username)
        print(password)
        if connection:
            cursor = connection.cursor()
            cursor.execute(f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'")
            user = cursor.fetchone()
            cursor.close()
            connection.close()
            if user:
                session['username'] = user[1]
                return render_template('urlpage.html',username=username)
            else:
                return "Invalid username or password."
        else:
            return "Failed to connect to the database."
    return render_template('login.html')

# Route for logout
# @app.route('/logout')
# def logout():
#     session.pop('username', None)
@app.route('/processurl', methods=['POST'])
def process_url():
    
    data = request.json.get('data')
    print("Received data:", data)
        # Example usage
    url = "https://kamarajengg.edu.in/"
    import time
    config = {
    'user': 'root',
    'password': '',
    'host': 'localhost',
    'database': 'url',
}

    connection = mysql.connector.connect(**config)

    status = "SCHEDULED"  # Initial status
    timstampData = time.strftime('%Y-%m-%d %H:%M:%S')
    id=0
    print(url)
    print(status)    
    cursor = connection.cursor()
    cursor.execute(f"INSERT INTO `urltable`(`id`,`url`, `status`, `timstampData`) VALUES ('{id}','{url}', '{status}', '{timstampData}')")
    connection.commit()
    
    ip_address = url_to_ip(url)
    if ip_address:
        print(f"The IP address of {url} is {ip_address}")
        nm = nmap.PortScanner()
        nm.scan(ip_address, '22-443')
        generate_pdf_report(ip_address, nm)
    else:
        print(f"Failed to resolve the IP address of {url}")
    
    

    # Process the data as needed (e.g., store it in a database)

    return jsonify({'message': 'Data received successfully'})
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

def generate_pdf_report(ip_address, nm):
    report_filename = f"scan_report_{ip_address}.pdf"
    doc = SimpleDocTemplate(report_filename, pagesize=letter)
    table_data = [['Port Number', 'Protocol', 'Services', 'Recommended Action']]

    # Extract information for the report
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

    # Create the table
    t = Table(table_data)
    t.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                           ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                           ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                           ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                           ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                           ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                           ('GRID', (0, 0), (-1, -1), 1, colors.black)]))

    # Add table to the document
    doc.build([t])

    print(f"PDF report generated successfully: {report_filename}")




if __name__ == '__main__':
    app.run(debug=True)
