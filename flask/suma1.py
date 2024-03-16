import time
from pprint import pprint
from zapv2 import ZAPv2

# API key and target URL
apiKey = 'gfpbjfihlmvbvkb1t5pjpe3ddl'
target = 'https://kamarajengg.edu.in/'

# Initialize ZAP API client
zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})

# AJAX Spider
print('AJAX Spider target {}'.format(target))
scanID = zap.ajaxSpider.scan(target)

# Wait for the AJAX Spider to complete
timeout = time.time() + 60*2   # 2 minutes from now
while zap.ajaxSpider.status != 'stopped':
    if time.time() > timeout:
        break
    print('AJAX Spider status: ' + zap.ajaxSpider.status)
    time.sleep(2)

print('AJAX Spider completed')

# Active Scan
print('Active Scanning target {}'.format(target))
scanID = zap.ascan.scan(target)

# Wait for the Active Scan to complete
while True:
    status = zap.ascan.status(scanID)
    if status == '100':
        print('Scan progress %: 100')
        break
    elif status == '50':
        print('Scan progress %: 50')
    else:
        print('Scan status: {}'.format(status))
    time.sleep(5)

print('Active Scan completed')

# Fetching vulnerabilities
alerts = zap.core.alerts(baseurl=target)

# Summary Variables
total_vulnerabilities = len(alerts)
vulnerabilities_grouped = {}
for alert in alerts:
    risk_rating = alert.get('risk')
    if risk_rating in vulnerabilities_grouped:
        vulnerabilities_grouped[risk_rating] += 1
    else:
        vulnerabilities_grouped[risk_rating] = 1

# Print Summary
print('Summary:')
print('i. No. of Total Vulnerabilities Identified: {}'.format(total_vulnerabilities))
print('ii. No. of Total Vulnerabilities Identified grouped on Risk Rating:')
for rating, count in vulnerabilities_grouped.items():
    print('   - {}: {}'.format(rating, count))

# Detailed Report
print('\nDetailed Report:')
for alert in alerts:
    print('i. Vulnerability Summary: {}'.format(alert.get('alert')))
    print('ii. Risk Rating: {}'.format(alert.get('risk')))
    print('iii. Confidence Rating: {}'.format(alert.get('confidence')))
    print('iv. Description: {}'.format(alert.get('description')))
    print('v. Details to Reproduce the Instance: {}'.format(alert.get('instances')[0].get('uri')))
    print('\n')
