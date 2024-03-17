import socket
from urllib.parse import urlparse
import nmap
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle

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

# Example usage
url = "https://kamarajengg.edu.in/"
ip_address = url_to_ip(url)
if ip_address:
    print(f"The IP address of {url} is {ip_address}")
    nm = nmap.PortScanner()
    nm.scan(ip_address, '22-443')
    generate_pdf_report(ip_address, nm)
else:
    print(f"Failed to resolve the IP address of {url}")
