from fpdf import FPDF
from zapv2 import ZAPv2
import socket
import nmap
from urllib.parse import urlparse
import time

# Function to convert URL to IP address
def url_to_ip(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        return None

# Function to generate ZAP report
def generate_zap_report(target, apiKey):
    zap = ZAPv2(apikey=apiKey)
    print("starting.......")

    # Ajax Spider
    zap.ajaxSpider.scan(target)
    while zap.ajaxSpider.status == 'running':
        print("Running ajaxspider")
        time.sleep(2)
        

    # Active Scan 
    scanID = zap.ascan.scan(target)
    print(scanID)
    print("active scan")
    while zap.ascan.status(scanID) != '100':
        time.sleep(5)

    # Fetching detailed report for ports
    print("got 100 status")
    alerts = zap.core.alerts(baseurl=target)
    num_of_alerts = len(alerts)
    print("complited active scan")

    return num_of_alerts, alerts

# Function to generate Nmap report
def generate_nmap_report(ip_address):
    nm = nmap.PortScanner()
    nm.scan(ip_address, '22-443')

    vulnerable_ports = []
    for host in nm.all_hosts():
        for port in nm[host]['tcp']:
            if nm[host]['tcp'][port]['state'] == 'open':
                vulnerable_ports.append({
                    'port_number': port,
                    'protocol': 'tcp',
                    'service': nm[host]['tcp'][port]['name'],
                    'recommended_action': 'Perform security assessment and apply necessary patches or configurations.'
                })

    num_of_vulnerable_ports = len(vulnerable_ports)

    return num_of_vulnerable_ports, vulnerable_ports

# Generate ZAP report
target = 'https://kamarajengg.edu.in/'
apiKey = 'gfpbjfihlmvbvkb1t5pjpe3ddl'
print("starting.......")
num_of_vulnerabilities, zap_report = generate_zap_report(target, apiKey)
print("starting.......")

# Generate Nmap report
ip_address = url_to_ip(target)
if ip_address:
    print("starting nmap.......")
    num_of_vulnerable_ports, nmap_report = generate_nmap_report(ip_address)
else:
    num_of_vulnerable_ports = 0
    nmap_report = []
    

# Generate PDF report
print("generating pdf........")
pdf = FPDF()
pdf.add_page()

# Header
pdf.set_font("Arial", size=12)
pdf.cell(200, 10, txt="Web Application and Open Ports Vulnerability Report", ln=True, align="C")
pdf.cell(200, 10, txt="Generated on: " + time.strftime("%Y-%m-%d %H:%M:%S"), ln=True, align="C")
pdf.ln(10)

# Web Application Vulnerabilities Section
pdf.set_font("Arial", size=10, style='B')
pdf.cell(200, 10, txt="Web Application Vulnerabilities", ln=True, align="L")
pdf.set_font("Arial", size=10)

pdf.cell(200, 10, txt=f"Total Vulnerabilities Identified: {num_of_vulnerabilities}", ln=True, align="L")

# Detailed Report for Web Application Vulnerabilities
for alert in zap_report:
    pdf.cell(200, 10, txt=f"Vulnerability: {alert['name']}", ln=True, align="L")
    pdf.cell(200, 10, txt=f"Risk Rating: {alert['risk']}", ln=True, align="L")
    pdf.cell(200, 10, txt=f"Confidence Rating: {alert['confidence']}", ln=True, align="L")
    pdf.cell(200, 10, txt=f"Description: {alert['description']}", ln=True, align="L")
    pdf.cell(200, 10, txt=f"Details to Reproduce: {alert['otherinfo']}", ln=True, align="L")
    pdf.ln()

# Open Vulnerable Ports Section
pdf.set_font("Arial", size=10, style='B')
pdf.cell(200, 10, txt="Open Vulnerable Ports", ln=True, align="L")
pdf.set_font("Arial", size=10)

pdf.cell(200, 10, txt=f"Total Vulnerable Ports Open: {num_of_vulnerable_ports}", ln=True, align="L")

# Detailed Report for Open Vulnerable Ports
for port_info in nmap_report:
    pdf.cell(200, 10, txt=f"Port Number: {port_info['port_number']}", ln=True, align="L")
    pdf.cell(200, 10, txt=f"Protocol: {port_info['protocol']}", ln=True, align="L")
    pdf.cell(200, 10, txt=f"Services: {port_info['service']}", ln=True, align="L")
    pdf.cell(200, 10, txt=f"Recommended Action: {port_info['recommended_action']}", ln=True, align="L")
    pdf.ln()

pdf.output("vulnerability_report.pdf")
