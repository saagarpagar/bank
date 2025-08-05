import streamlit as st
import hashlib
from datetime import datetime

# ------------------------
# Helper Functions
# ------------------------

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

# ------------------------
# Session State Initialization
# ------------------------

if 'users' not in st.session_state:
    st.session_state.users = {}

if 'current_user' not in st.session_state:
    st.session_state.current_user = None

# ------------------------
# App Title and Menu
# ------------------------

st.title("Banking Application")

menu = st.sidebar.selectbox("Menu", ["Login", "Sign Up", "Dashboard", "Logout"])

# ------------------------
# Sign Up
# ------------------------

if menu == "Sign Up":
    st.header("Create an Account")
    name = st.text_input("Full Name")
    email = st.text_input("Email Address")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("Sign Up"):
        if not name or not email or not password:
            st.warning("Please fill all fields.")
        elif password != confirm_password:
            st.error("Passwords do not match.")
        elif len(password) < 6:
            st.warning("Password must be at least 6 characters long.")
        elif email in st.session_state.users:
            st.error("An account with this email already exists.")
        else:
            st.session_state.users[email] = {
                "name": name,
                "password": hash_password(password),
                "balance": 1000.0,
                "history": [(datetime.now(), "Account created with ₹1000 initial balance")]
            }
            st.success("Account created successfully. You can now log in.")

# ------------------------
# Login
# ------------------------

if menu == "Login":
    st.header("Login")
    email = st.text_input("Email", key="login_email")
    password = st.text_input("Password", type="password", key="login_password")

    if st.button("Login"):
        if email in st.session_state.users:
            if st.session_state.users[email]["password"] == hash_password(password):
                st.session_state.current_user = email
                st.success(f"Welcome, {st.session_state.users[email]['name']}")
            else:
                st.error("Incorrect password.")
        else:
            st.error("No account found with that email.")

# ------------------------
# Dashboard
# ------------------------

if menu == "Dashboard":
    if st.session_state.current_user:
        user = st.session_state.users[st.session_state.current_user]
        st.header(f"Welcome, {user['name']}")
        st.metric("Balance", f"₹{user['balance']:,.2f}")

        action = st.selectbox("Choose Action", ["Credit", "Debit", "Transaction History"])

        if action == "Credit":
            amount = st.number_input("Amount to credit", min_value=1.0, step=1.0)
            if st.button("Add Funds"):
                user["balance"] += amount
                user["history"].append((datetime.now(), f"Credited ₹{amount:,.2f}"))
                st.success(f"₹{amount:,.2f} credited successfully.")

        elif action == "Debit":
            amount = st.number_input("Amount to debit", min_value=1.0, step=1.0)
            if st.button("Withdraw"):
                if amount > user["balance"]:
                    st.error("Insufficient balance.")
                else:
                    user["balance"] -= amount
                    user["history"].append((datetime.now(), f"Debited ₹{amount:,.2f}"))
                    st.success(f"₹{amount:,.2f} debited successfully.")

        elif action == "Transaction History":
            st.subheader("Transaction History")
            if user["history"]:
                for time, desc in reversed(user["history"]):
                    st.text(f"{time.strftime('%d-%b %Y %I:%M %S %p')} - {desc}")
            else:
                st.info("No transactions found.")
    else:
        st.warning("Please login to access the dashboard.")

# ------------------------
# Logout
# ------------------------

if menu == "Logout":
    if st.session_state.current_user:
        name = st.session_state.users[st.session_state.current_user]["name"]
        st.session_state.current_user = None
        st.success(f"{name}, you have been logged out.")
    else:
        st.info("You are not logged in.")
