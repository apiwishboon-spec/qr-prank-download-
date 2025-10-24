from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os, smtplib, random

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")

# Email config
EMAIL = os.getenv("EMAIL_ADDR")
PASSWORD = os.getenv("EMAIL_APP_PASS")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))

# OTP store
active_otps = {}

def send_otp_email(recipient, otp):
    msg = MIMEMultipart()
    msg["From"] = EMAIL
    msg["To"] = recipient
    msg["Subject"] = "Your OTP for Boon’s Download Portal"
    msg.attach(MIMEText(f"Your One-Time Password is: {otp}\n\nIt expires in 10 minutes.", "plain"))
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as s:
        s.starttls()
        s.login(EMAIL, PASSWORD)
        s.send_message(msg)

@app.route("/")
def terms():
    return render_template("terms.html")

@app.route("/request_otp", methods=["POST"])
def request_otp():
    email = request.form.get("email")
    agree = request.form.get("agree")
    if not agree:
        flash("You must agree to the terms before continuing.")
        return redirect(url_for("terms"))
    if not email:
        flash("Email address is required.")
        return redirect(url_for("terms"))

    otp = str(random.randint(100000, 999999))
    expiry = datetime.utcnow() + timedelta(minutes=10)
    active_otps[email] = {"otp": otp, "expiry": expiry}

    try:
        send_otp_email(email, otp)
    except Exception as e:
        flash(f"Failed to send OTP: {e}")
        return redirect(url_for("terms"))

    session["email"] = email
    flash("OTP sent to your email! Please check your inbox.")
    return redirect(url_for("verify"))

@app.route("/verify", methods=["GET", "POST"])
def verify():
    email = session.get("email")
    if not email:
        return redirect(url_for("terms"))

    if request.method == "POST":
        user_otp = request.form.get("otp")
        record = active_otps.get(email)
        if not record:
            flash("No OTP found. Please request again.")
            return redirect(url_for("terms"))

        if datetime.utcnow() > record["expiry"]:
            flash("OTP expired. Please request a new one.")
            active_otps.pop(email, None)
            return redirect(url_for("terms"))

        if user_otp == record["otp"]:
            active_otps.pop(email, None)
            session["verified"] = True
            return redirect(url_for("download"))
        else:
            flash("Incorrect OTP. Please try again.")

    return render_template("verify.html", email=email)

@app.route("/download")
def download():
    if not session.get("verified"):
        return redirect(url_for("terms"))
    return render_template("download.html")

@app.route("/static/downloads/<path:filename>")
def serve_download(filename):
    return send_from_directory("static/downloads", filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
