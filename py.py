import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import base64
import os
import json
import random
import string

DATA_FILE = "data.json"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_key(password):
    hashed = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

def generate_random_password(length=10):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def encrypt_text(text, password):
    key = create_key(password)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted, password):
    try:
        key = create_key(password)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted.encode()).decode()
    except:
        return None

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

if "users" not in st.session_state:
    st.session_state.users = load_data()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "page" not in st.session_state:
    st.session_state.page = "home"

def sidebar():
    if st.session_state.logged_in:
        st.sidebar.title(f"👋 {st.session_state.logged_in}")
        return st.sidebar.selectbox("Navigation", ["Encrypt Data", "Decrypt Data", "View Saved Data"])
    return None

def home():
    st.title("🔐 Secure Data Vault")
    st.write("Please login or create an account to continue.")
    if st.button("Login"):
        st.session_state.page = "login"
        st.rerun()
    if st.button("Create Account"):
        st.session_state.page = "signup"
        st.rerun()

def signup():
    st.title("🧾 Create Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        if username in st.session_state.users:
            st.error("User already exists.")
        elif username and password:
            st.session_state.users[username] = {"password": hash_password(password), "data": {}}
            save_data(st.session_state.users)
            st.session_state.page = "login"
            st.rerun()
        else:
            st.warning("Please fill in all fields.")

def login():
    st.title("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        user = st.session_state.users.get(username)
        if user and user["password"] == hash_password(password):
            st.session_state.logged_in = username
            st.session_state.failed_attempts = 0
            st.session_state.page = "dashboard"
            st.rerun()
        else:
            st.error("Invalid credentials.")

def view_saved_data():
    st.title(f"📂 View Saved Data - {st.session_state.logged_in}")
    user_data = st.session_state.users.get(st.session_state.logged_in, {}).get("data", {})
    if not user_data:
        st.write("No data found.")
    else:
        for title, data in user_data.items():
            st.write(f"**{title}**: {data['enc']}")

def dashboard():
    selection = sidebar()
    if selection == "Encrypt Data":
        st.title("🔐 Encrypt Data")
        title = st.text_input("Enter Title")
        text = st.text_area("Enter Data to Encrypt")
        if st.button("Encrypt"):
            if title and text:
                password = generate_random_password()
                encrypted = encrypt_text(text, password)
                st.session_state.users[st.session_state.logged_in]["data"][title] = {
                    "enc": encrypted
                }
                save_data(st.session_state.users)
                st.success("Data Encrypted!")
                st.code(encrypted)
                st.info(f"🔑 Your Password: {password}")
            else:
                st.warning("All fields are required.")

    elif selection == "Decrypt Data":
        st.title("🔓 Decrypt Data")
        if st.session_state.failed_attempts >= 3:
            st.warning("Too many failed attempts. You have been logged out.")
            st.session_state.logged_in = None
            st.session_state.failed_attempts = 0
            st.session_state.page = "home"
            st.rerun()
            return

        title = st.text_input("Enter Title")
        password = st.text_input("Enter Password", type="password")
        if st.button("Decrypt"):
            data = st.session_state.users[st.session_state.logged_in]["data"].get(title)
            if data:
                decrypted = decrypt_text(data["enc"], password)
                if decrypted:
                    st.success("Decryption Successful!")
                    st.code(decrypted)
                    st.session_state.failed_attempts = 0
                else:
                    st.session_state.failed_attempts += 1
                    left = 3 - st.session_state.failed_attempts
                    st.error(f"Wrong password. Attempts left: {left}")
            else:
                st.error("Title not found.")

    elif selection == "View Saved Data":
        view_saved_data()

    # Add logout button at the bottom of every page
    st.markdown("---")
    if st.button("🚪 Logout"):
        st.session_state.logged_in = None
        st.session_state.page = "home"
        st.rerun()

if st.session_state.page == "home":
    home()
elif st.session_state.page == "signup":
    signup()
elif st.session_state.page == "login":
    login()
elif st.session_state.page == "dashboard" and st.session_state.logged_in:
    dashboard()
else:
    st.session_state.page = "home"
