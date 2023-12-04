from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import random
def generateOTP(email):
    verification_code= str(random.randint(1000, 9999))

    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "anonymous2392000@gmail.com"
    sender_password = "jeqs zdxs icjb azqf"

    recipient_email = email

    subject = "Verification Code"
    message = f"Your DCloud verification code is: {verification_code}"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject

# Attach the message
    msg.attach(MIMEText(message, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()
        print("Verification code sent successfully.")
        return verification_code
    except Exception as e:
        print("An error occurred: ", str(e))
