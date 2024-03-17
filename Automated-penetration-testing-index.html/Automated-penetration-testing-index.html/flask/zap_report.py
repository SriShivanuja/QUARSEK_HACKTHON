import time
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from zapv2 import ZAPv2

# API key and target URL
apiKey = 'gfpbjfihlmvbvkb1t5pjpe3ddl'
target = 'https://www.ramakrishna.com/'

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
        print('Active Scan completed')
        break
    else:
        print('Scan status: {}'.format(status))
        time.sleep(5)

print('Active Scan completed')

# Fetching vulnerabilities
alerts = zap.core.alerts(baseurl=target)

# Create a PDF report
pdf_file = "web_vulner_report.pdf"
c = canvas.Canvas(pdf_file, pagesize=letter)
c.setFont("Helvetica", )
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
c.drawString(100, 750, 'Summary:')
c.drawString(100, 730, 'i. No. of Total Vulnerabilities Identified: {}'.format(total_vulnerabilities))
c.drawString(100, 710, 'ii. No. of Total Vulnerabilities Identified grouped on Risk Rating:')
y_pos = 690
for rating, count in vulnerabilities_grouped.items():
    c.drawString(120, y_pos, '- {}: {}'.format(rating, count))
    y_pos -= 20

# Detailed Report
c.drawString(100, 670, '\nDetailed Report:')
y_pos -= 50
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

# Save the PDF
c.save()

print("PDF report generated successfully: {}".format(pdf_file))
