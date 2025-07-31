import streamlit as st
import smtplib
import ssl
import random
import string
import hashlib
import os
from datetime import datetime, timedelta

# --- Helper Functions ---

def generate_otp(length=6):
    """Generate a numeric OTP"""
    return ''.join(random.choices(string.digits, k=length))

def send_email_otp(receiver_email, otp):
    """Send OTP to user's email via Gmail SMTP"""
    sender_email = os.getenv("EMAIL_ADDRESS")
    sender_password = os.getenv("EMAIL_APP_PASSWORD")

    # Check if credentials are set
    if not sender_email:
        st.error("📧 Sender email not configured. Contact admin.")
        return False
    if not sender_password:
        st.error("🔐 Email app password not set. Contact admin.")
        return False

    # Email content
    subject = "🔐 One-Time Password (OTP) for Verification"
    body = f"""
Hello,

Your OTP is: **{otp}**

This code is valid for 5 minutes. Do not share it with anyone.

Thank you,
Banking App Security
"""
    message = f"Subject: {subject}\n\n{body}"

    # Send email
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, message)
        return True
    except smtplib.SMTPAuthenticationError as e:
        st.error("📛 Authentication failed. Check your email and app password.")
        st.exception(e)
        return False
    except smtplib.SMTPRecipientsRefused as e:
        st.error("❌ The recipient email address is invalid or rejected.")
        st.exception(e)
        return False
    except Exception as e:
        st.error("💥 Failed to send OTP. An unexpected error occurred.")
        st.exception(e)
        return False

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()


# --- Initialize Session State ---
if 'users' not in st.session_state:
    st.session_state.users = {}

if 'current_user' not in st.session_state:
    st.session_state.current_user = None

if 'otp_data' not in st.session_state:
    st.session_state.otp_data = None  # {"otp": "...", "email": "...", "expires": datetime}


# --- App Title ---
st.title("🔐 Secure Banking App with Email OTP")

menu = st.sidebar.selectbox("🔐 Menu", ["Login", "Sign Up", "Dashboard", "Logout"])

# --- Sign Up ---
if menu == "Sign Up":
    st.header("📝 Create an Account")
    name = st.text_input("Full Name")
    email = st.text_input("Email Address")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("📨 Send OTP"):
        # Validation
        if not name or not email or not password:
            st.warning("Please fill all fields.")
        elif password != confirm_password:
            st.error("Passwords do not match!")
        elif len(password) < 6:
            st.warning("Password must be at least 6 characters long.")
        elif email in st.session_state.users:
            st.error("An account with this email already exists.")
        else:
            # Generate OTP
            otp = generate_otp()
            expires_at = datetime.now() + timedelta(minutes=5)

            # Store OTP temporarily
            st.session_state.otp_data = {
                "otp": otp,
                "email": email,
                "name": name,
                "password": hash_password(password),
                "expires": expires_at
            }

            # Send OTP
            with st.spinner("Sending OTP..."):
                if send_email_otp(email, otp):
                    st.success(f"✅ OTP has been sent to **{email}**! Check your inbox (and spam folder).")
                else:
                    st.error("❌ Failed to send OTP. Please try again later.")

    # OTP Verification Section
    if st.session_state.otp_data:
        st.markdown("---")
        entered_otp = st.text_input("Enter the 6-digit OTP", max_chars=6)
        if st.button("✅ Verify OTP"):
            data = st.session_state.otp_data
            if datetime.now() > data["expires"]:
                st.error("⏰ OTP has expired! Please request a new one.")
                st.session_state.otp_data = None
            elif entered_otp == data["otp"]:
                # Save user
                st.session_state.users[data["email"]] = {
                    "name": data["name"],
                    "password": data["password"],
                    "balance": 1000.0,
                    "history": [(datetime.now(), "✅ Account created with ₹1000 initial balance")]
                }
                st.success("🎉 Account created successfully! You can now log in.")
                st.session_state.otp_data = None  # Clear OTP after success
            else:
                st.error("❌ Invalid OTP. Try again.")

# --- Login ---
if menu == "Login":
    st.header("🔑 Login")
    email = st.text_input("Email Address", key="login_email")
    password = st.text_input("Password", type="password", key="login_password")

    if st.button("🔓 Login"):
        if email in st.session_state.users:
            hashed_pw = hash_password(password)
            if st.session_state.users[email]["password"] == hashed_pw:
                st.session_state.current_user = email
                st.success(f"✅ Welcome back, {st.session_state.users[email]['name']}!")
            else:
                st.error("❌ Incorrect password.")
        else:
            st.error("❌ No account found with that email.")

# --- Dashboard ---
if menu == "Dashboard":
    if st.session_state.current_user:
        user = st.session_state.users[st.session_state.current_user]
        st.header(f"🏠 Welcome, {user['name']}")

        st.metric("💰 Balance", f"₹{user['balance']:,.2f}")

        action = st.selectbox("Choose Action", ["📥 Credit", "📤 Debit", "📋 Transaction History"])

        if action == "📥 Credit":
            amount = st.number_input("Amount to credit", min_value=1.0, step=1.0)
            if st.button("Add Funds"):
                user["balance"] += amount
                user["history"].append((datetime.now(), f"📥 Credited ₹{amount:,.2f}"))
                st.success(f"✅ ₹{amount:,.2f} credited!")

        elif action == "📤 Debit":
            amount = st.number_input("Amount to debit", min_value=1.0, step=1.0)
            if st.button("Withdraw"):
                if amount > user["balance"]:
                    st.error("❌ Insufficient funds!")
                else:
                    user["balance"] -= amount
                    user["history"].append((datetime.now(), f"📤 Withdrew ₹{amount:,.2f}"))
                    st.success(f"✅ ₹{amount:,.2f} debited!")

        elif action == "📋 Transaction History":
            st.subheader("📜 Transaction History")
            if user["history"]:
                for time, desc in reversed(user["history"]):
                    st.text(f"{time.strftime('%d-%b %Y %I:%M %S %p')} → {desc}")
            else:
                st.info("📭 No transactions yet.")

    else:
        st.warning("Please log in to access the dashboard.")
        st.info("Go to **Login** from the sidebar.")

# --- Logout ---
if menu == "Logout":
    if st.session_state.current_user:
        name = st.session_state.users[st.session_state.current_user]["name"]
        st.session_state.current_user = None
        st.success(f"👋 {name}, you've been logged out.")
    else:
        st.info("You are not logged in.")
