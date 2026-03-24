"""
Email operations for the Customer Operations Platform.

This module provides tools for sending emails to customers via SMTP.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any
from langchain_core.tools import tool

from config import email_config


def create_smtp_connection():
    """
    Create and authenticate an SMTP connection.

    Returns:
        Authenticated SMTP connection object
    """
    if email_config.use_tls:
        server = smtplib.SMTP(email_config.smtp_host, email_config.smtp_port)
        server.starttls()
    else:
        server = smtplib.SMTP(email_config.smtp_host, email_config.smtp_port)

    if email_config.smtp_user and email_config.smtp_password:
        server.login(email_config.smtp_user, email_config.smtp_password)

    return server


@tool
def send_customer_email(
    to_address: str,
    subject: str,
    body: str,
    cc: Optional[List[str]] = None,
    reply_to: Optional[str] = None,
    is_html: bool = False
) -> Dict[str, Any]:
    """
    Send an email to a customer.

    Sends an email through the configured SMTP server. This tool performs
    an external action by sending data outside the system boundary.

    Args:
        to_address: The recipient's email address
        subject: Email subject line
        body: Email body content
        cc: Optional list of CC recipients
        reply_to: Optional reply-to address
        is_html: If True, send as HTML email. Default is plain text.

    Returns:
        Dictionary containing send status and message ID

    Example:
        result = send_customer_email(
            to_address="customer@example.com",
            subject="Your Support Request Update",
            body="Hello, your ticket has been resolved..."
        )
    """
    msg = MIMEMultipart("alternative") if is_html else MIMEMultipart()

    msg["From"] = email_config.from_address
    msg["To"] = to_address
    msg["Subject"] = subject

    if cc:
        msg["Cc"] = ", ".join(cc)

    if reply_to:
        msg["Reply-To"] = reply_to

    if is_html:
        msg.attach(MIMEText(body, "html"))
    else:
        msg.attach(MIMEText(body, "plain"))

    all_recipients = [to_address]
    if cc:
        all_recipients.extend(cc)

    server = create_smtp_connection()
    try:
        server.sendmail(email_config.from_address, all_recipients, msg.as_string())
        return {
            "status": "sent",
            "to": to_address,
            "subject": subject,
            "cc": cc or [],
        }
    finally:
        server.quit()


@tool
def send_bulk_email(
    recipients: List[Dict[str, str]],
    subject_template: str,
    body_template: str
) -> Dict[str, Any]:
    """
    Send bulk emails to multiple recipients.

    Sends personalized emails to a list of recipients using templates.
    Variables in templates are replaced with recipient-specific values.

    Args:
        recipients: List of dicts with 'email' and personalization fields
        subject_template: Subject template with {field} placeholders
        body_template: Body template with {field} placeholders

    Returns:
        Dictionary with send results for each recipient

    Example:
        results = send_bulk_email(
            recipients=[
                {"email": "alice@example.com", "name": "Alice"},
                {"email": "bob@example.com", "name": "Bob"}
            ],
            subject_template="Hello {name}!",
            body_template="Dear {name}, thank you for your purchase."
        )
    """
    server = create_smtp_connection()
    results = {"sent": [], "failed": []}

    try:
        for recipient in recipients:
            try:
                email_addr = recipient["email"]
                subject = subject_template.format(**recipient)
                body = body_template.format(**recipient)

                msg = MIMEText(body, "plain")
                msg["From"] = email_config.from_address
                msg["To"] = email_addr
                msg["Subject"] = subject

                server.sendmail(email_config.from_address, [email_addr], msg.as_string())
                results["sent"].append(email_addr)
            except Exception as e:
                results["failed"].append({"email": recipient.get("email"), "error": str(e)})
    finally:
        server.quit()

    return results
