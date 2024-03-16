import socket
from urllib.parse import urlparse

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

# Example usage
url = "https://kamarajengg.edu.in/"
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
