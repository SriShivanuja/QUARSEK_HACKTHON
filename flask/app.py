from flask import Flask, request, render_template, send_file
import mysql.connector
import time
import socket
from urllib.parse import urlparse
import threading
from zapv2 import ZAPv2
import time 
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


@app.route('/login')
def login():
    return render_template('')



@app.route('/process', methods=['POST'])
def process():
    url1 = request.form['url']
    import time

    status = "SCHEDULED"  # Initial status
    timstampData = time.strftime('%Y-%m-%d %H:%M:%S')
    id=0
    print(url1)
    print(status)    
    cursor = connection.cursor()
    cursor.execute(f"INSERT INTO `urltable`(`id`,`url`, `status`, `timstampData`) VALUES ('{id}','{url1}', '{status}', '{timstampData}')")
    connection.commit()
    
    

    #Start threads for running both ZAP and Nmap
    # zap_thread = threading.Thread(target=run_zap, args=(url1,))
    # nmap_thread = threading.Thread(target=run_nmap, args=(url1,))
    
    # zap_thread.start()
    # nmap_thread.start()
    #####################################################################//nmap//#################################################
    
    ip_address = url_to_ip(url1)
    if ip_address:
        print(f"The IP address of {url1} is {ip_address}")
    else:
        print(f"Failed to resolve the IP address of {url1}")
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
        lport = list(nm[host][proto].keys())
        lport.sort()
        for port in lport:
            print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

    #result=run_nmap(url1)
    #print(result)
    ######################################################################//nmap//##########################################  
    
    import time
    from zapv2 import ZAPv2

    # The URL of the application to be tested
    
    # Change to match the API key set in ZAP, or use None if the API key is disabled
    apiKey = 'gfpbjfihlmvbvkb1t5pjpe3ddl'

    # By default ZAP API client will connect to port 8080
    zap = ZAPv2(apikey=apiKey)
    # Use the line below if ZAP is not listening on port 8080, for example, if listening on port 8090

    # Ajax Spider
    print('Ajax Spider target {}'.format(url1))
    scanID = zap.ajaxSpider.scan(url1)

    timeout = time.time() + 60*2   # 2 minutes from now
    # Loop until the ajax spider has finished or the timeout has exceeded
    while zap.ajaxSpider.status == 'running':
        if time.time() > timeout:
            break
        print('Ajax Spider status: ' + zap.ajaxSpider.status)
        time.sleep(2)

    print('Ajax Spider completed')

    # Active Scan
    print('Active Scanning target {}'.format(url1))
    scanID = zap.ascan.scan(url1)

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
    arr=zap.core.alerts(baseurl=url1)
    num_of_alert1 = zap.core.number_of_alerts(baseurl=url1)
    print(num_of_alert1)
    print('Active Scan completed')

    
    return render_template('index.html', url1=url1, status=status)


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
        lport = list(nm[host][proto].keys())
        lport.sort()
        for port in lport:
            print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

                    
                


if __name__ == '__main__':
  
    app.run(debug=True)
