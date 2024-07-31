import gradio as gr
from email.parser import Parser
from email.policy import default
import re

def analyze_email_headers(header_string):
    parser = Parser(policy=default)
    email_message = parser.parsestr(header_string)
    
    # Extract useful information from the headers
    results = {
        "From": email_message['From'],
        "To": email_message['To'],
        "Subject": email_message['Subject'],
        "Date": email_message['Date'],
        "Message-ID": email_message['Message-ID']
    }

    # Extract received headers to trace the email path
    received_headers = email_message.get_all('Received')
    if received_headers:
        results["Received Path"] = received_headers
    else:
        results["Received Path"] = ["No Received headers found."]

    # Check for common spoofing signs
    spoofing_signs = check_for_spoofing(received_headers)

    return results, spoofing_signs

def check_for_spoofing(received_headers):
    # Simple spoofing checks
    if not received_headers:
        return "No received headers to analyze for spoofing."

    spoofing_warnings = []
    
    # Check if the email passed through unusual number of servers
    if len(received_headers) > 5:
        spoofing_warnings.append("Email passed through an unusually high number of servers.")
    
    # Check for mismatched Received-SPF or DKIM results
    for header in received_headers:
        if "spf=fail" in header.lower():
            spoofing_warnings.append("SPF check failed.")
        if "dkim=fail" in header.lower():
            spoofing_warnings.append("DKIM check failed.")
    
    if not spoofing_warnings:
        spoofing_warnings.append("No obvious signs of spoofing detected.")
    
    return spoofing_warnings

def format_results(results, spoofing_signs):
    output = ""
    for key, value in results.items():
        if key == "Received Path":
            output += f"{key}:\n"
            for header in value:
                output += f"  - {header}\n"
        else:
            output += f"{key}: {value}\n"
    
    output += "\nSpoofing Analysis:\n"
    for sign in spoofing_signs:
        output += f"- {sign}\n"
    
    return output

iface = gr.Interface(
    fn=lambda header_string: format_results(*analyze_email_headers(header_string)),
    inputs=gr.Textbox(lines=20, placeholder="Paste email headers here..."),
    outputs=gr.Textbox(),
    description="Input raw email headers to extract and analyze key information such as sender, recipient, subject, date, and the mail path. Includes a basic check for email spoofing."
)

iface.launch()
