from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, TransportError, NotFoundError
from requests.auth import HTTPBasicAuth
from openpyxl.styles import PatternFill
import pandas as pd
import urllib3,requests, ssl, vt, os, asyncio, time, typer, json, smtplib, base64, openpyxl, mimetypes, zipfile, subprocess, shutil
from email.message import EmailMessage
from email.utils import formataddr
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime



def main():

    print("\n [+] Sending Alert Email . . .")
    port = 587  # For starttls
    smtp_server = "smtp.gmail.com"
    sender_email = "prajshete17@gmail.com"
    receiver_email = "praj@pkfalgosmic.com"
    p = "bHBjciBvamdkIGdnemogc29oaQ=="
    p = base64.b64decode(p) 
    p = p.decode("ascii")
    file_names = ['output_http.xlsx', 'output_dns.xlsx']
    in_dir = "C:/Users/prajs_28/OneDrive/Desktop/PKF ALgosmic/Automate IR/Automate-Incident-Response/CSV Results"
    
    body = f"""\

    Network Connections have been detected to the following external malicious IP/DNS addresses:

    IP's:
    

    DNS's:
    
    

    Review the attached log files in ZIP for more details !
    """

    # Create the email message
    message = MIMEMultipart()
    message["From"] = formataddr(("Elastic Alert", sender_email))
    message["To"] = receiver_email
    message["Subject"] = "!! ALERT - Malicious Network Connections !!"
  
    # Add body to email
    message.attach(MIMEText(body, "plain"))
    
    #Attach Log Files
    files = [f for f in os.listdir(in_dir) if os.path.isfile(os.path.join(in_dir, f))]

    for file_name in file_names:
        file_path = os.path.join(in_dir, file_name)
        if os.path.exists(file_path):
            with open(file_path, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename= {os.path.basename(file_name)}")
                message.attach(part)
        else:
            print(f"File not found: {file_path}")

    
    today = datetime.now().strftime("%m-%d")
    dir_to_zip = f"C:/Users/prajs_28/Downloads/Compromised_logs_{today}"
    zip_attachment = f"C:/Users/prajs_28/Downloads/Compromised_logs_{today}"
    shutil.make_archive(zip_attachment, 'zip', dir_to_zip)
    zip_file = f"{zip_attachment}.zip"
    # Attach zip file to email
    if os.path.exists(zip_file):
        with open(zip_file, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename=Compromised_logs_{today}.zip")
            message.attach(part)
    else:
        print(f"Zip file not found: {zip_attachment}")


    #Sending Email
    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_server, port) as server:
        server.starttls(context=context)
        server.login(sender_email, p)
        server.sendmail(sender_email, receiver_email, message.as_string())
    

    print("[+] Email Successfully Sent !!")

if __name__==("__main__"):
    main()