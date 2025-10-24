# app.py
import os
import random
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import (
    Flask, render_template, request, redirect, url_for,
    jsonify, session, send_from_directory, flash
)
from dotenv import load_dotenv

# Load environment variables from .env in development
load_dotenv()

# --- CONFIG ---
EMAIL_ADDRESS = os.getenv("EMAIL_ADDR")          # e.g. your_email@gmail.com
EMAIL_PASSWORD = os.getenv("EMAIL_APP_PASS")     # Gmail app password (if using Gmail)
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", "10"))
OTP_LENGTH = int(os.getenv("OTP_LENGTH", "6"))

# Flask app
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET", os.urandom(24))

# In-memory OTP store: { email: {"otp": str, "expiry": datetime, "attempts": int} }
otp_store = {}

# Rate limiting knobs (very simple)
REQUEST_LIMIT_PER_EMAIL = 5  # allowed outstanding OTP requests per email
MAX_VERIFY_ATTEMPTS = 5      # max wrong OTP attempts before invalidation

# Helper: generate OTP
def generate_otp(length=6):
    return ''.join(str(random.randint(0, 9)) for _ in range(length))

# Helper: send email
def send_email(to_email, subject, body):
    msg = MIMEMultipart()
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
    except Exception as e:
        app.logger.error("Failed to send email: %s", e)
        raise

# --- ROUTES ---

@app.route("/")
def terms():
    """
    Terms page: user must check 'I agree' to proceed.
    """
    return render_template("terms.html")

@app.route("/agree", methods=["POST"])
def agree():
    """
    User agrees to terms. We set a session flag and redirect to email request form.
    """
    agreed = request.form.get("agree") == "on"
    if not agreed:
        flash("You must agree to the terms to continue.", "danger")
        return redirect(url_for("terms"))
    session["agreed_to_terms"] = True
    # Clear any previous OTP state in session
    session.pop("email_verified", None)
    return redirect(url_for("request_otp_page"))

@app.route("/request-otp", methods=["GET"])
def request_otp_page():
    if not session.get("agreed_to_terms"):
        return redirect(url_for("terms"))
    return render_template("verify.html", stage="request")  # stage toggles UI

@app.route("/request-otp", methods=["POST"])
def request_otp():
    """
    API to request an OTP. Expects form field `email`.
    Sends a 6-digit OTP to that email and stores expiry info.
    """
    if not session.get("agreed_to_terms"):
        return redirect(url_for("terms"))

    email = request.form.get("email", "").strip().lower()
    if not email:
        flash("Please enter a valid email address.", "danger")
        return redirect(url_for("request_otp_page"))

    # Basic rate control: count outstanding OTPs for this email
    rec = otp_store.get(email)
    if rec and rec.get("requests", 0) >= REQUEST_LIMIT_PER_EMAIL:
        flash("Too many OTP requests for this email. Try again later.", "danger")
        return redirect(url_for("request_otp_page"))

    otp = generate_otp(OTP_LENGTH)
    expiry = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)

    # Store OTP with metadata
    otp_store[email] = {
        "otp": otp,
        "expiry": expiry,
        "attempts": 0,
        "requests": (otp_store.get(email, {}).get("requests", 0) + 1)
    }

    # Send email
    body = (
        f"Your One-Time Password (OTP) to access the download is: {otp}\n\n"
        f"This code expires in {OTP_EXPIRY_MINUTES} minutes.\n\n"
        "If you did not request this, ignore this email."
    )
    try:
        send_email(email, "Your OTP for download access", body)
    except Exception as e:
        flash("Failed to send OTP email. Check server logs and SMTP configuration.", "danger")
        # remove stored OTP on failure
        otp_store.pop(email, None)
        return redirect(url_for("request_otp_page"))

    # save email to session so we know who is verifying
    session["otp_email"] = email
    flash(f"OTP sent to {email} — check your inbox (and spam).", "success")
    return redirect(url_for("verify_otp_page"))

@app.route("/verify-otp", methods=["GET"])
def verify_otp_page():
    if not session.get("agreed_to_terms"):
        return redirect(url_for("terms"))
    # If email in session, show OTP entry UI
    return render_template("verify.html", stage="verify")

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    email = session.get("otp_email")
    if not email:
        flash("No OTP request in progress. Please request an OTP first.", "danger")
        return redirect(url_for("request_otp_page"))

    code = request.form.get("otp", "").strip()
    rec = otp_store.get(email)

    if not rec:
        flash("No OTP record found or it expired. Request a new OTP.", "danger")
        return redirect(url_for("request_otp_page"))

    # Expiry check
    if datetime.utcnow() > rec["expiry"]:
        otp_store.pop(email, None)
        flash("OTP has expired. Please request a new one.", "warning")
        return redirect(url_for("request_otp_page"))

    # Attempts check
    if rec["attempts"] >= MAX_VERIFY_ATTEMPTS:
        otp_store.pop(email, None)
        flash("Too many invalid attempts. OTP invalidated. Request a new OTP.", "danger")
        return redirect(url_for("request_otp_page"))

    if code == rec["otp"]:
        # Success: mark session as verified and remove stored OTP
        session["email_verified"] = True
        otp_store.pop(email, None)
        flash("✅ OTP verified — you may download the file.", "success")
        return redirect(url_for("download_page"))
    else:
        rec["attempts"] += 1
        otp_store[email] = rec
        remaining = MAX_VERIFY_ATTEMPTS - rec["attempts"]
        flash(f"Invalid OTP. {remaining} attempts left before invalidation.", "danger")
        return redirect(url_for("verify_otp_page"))

@app.route("/download", methods=["GET"])
def download_page():
    # ensure user agreed and verified
    if not session.get("agreed_to_terms") or not session.get("email_verified"):
        flash("You must agree and verify email to access the download.", "danger")
        return redirect(url_for("terms"))
    # Show download page
    return render_template("download.html")

@app.route("/download/file", methods=["GET"])
def download_file():
    # final file-serving endpoint; ensure verification
    if not session.get("agreed_to_terms") or not session.get("email_verified"):
        flash("You must verify before downloading.", "danger")
        return redirect(url_for("terms"))
    # serve static file (put your file in static/downloads/)
    filename = "prank.zip"  # change if needed
    downloads_dir = os.path.join(app.static_folder, "downloads")
    return send_from_directory(downloads_dir, filename, as_attachment=True)

# Simple logout/cleanup route (optional)
@app.route("/reset", methods=["GET"])
def reset():
    session.clear()
    flash("Session reset.", "info")
    return redirect(url_for("terms"))

if __name__ == "__main__":
    app.run(debug=True)
