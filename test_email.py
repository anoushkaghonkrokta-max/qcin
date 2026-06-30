import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST="smtp.mx18.com"
SMTP_PORT=587
SMTP_USERNAME="mukesh_shukla_108877"
SMTP_PASSWORD="mx18_bXDnnTQceMdKCVtwHTKb6beJM8cQSpCPLToCBN7V68I1e44c"
FROM_EMAIL="notification@qci.org.in"
To_EMAIL="nishant.sengar@sapple.co.in,anoushka.ghonkrokta@gmail.com"

msg = MIMEMultipart()
msg["From"]    = FROM_EMAIL
msg["To"]      = To_EMAIL
msg["Subject"] = "QCI Test Email"
msg.attach(MIMEText("If you see this, SMTP is working!", "plain"))

try:
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
        s.starttls(context=ssl.create_default_context())
        s.login(SMTP_USERNAME, SMTP_PASSWORD)
        s.sendmail(FROM_EMAIL, To_EMAIL.split(","), msg.as_string())
    print("✓ Email sent successfully!")
except Exception as e:
    print(f"✗ Failed: {e}")