import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Constants
DATA_INFO = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60  # in seconds

# Session state initialization
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Utility functions
def load_data():
    if os.path.exists(DATA_INFO):
        with open(DATA_INFO, "r") as file:
            return json.load(file)
    return {}

def save_data(data):
    with open(DATA_INFO, "w") as file:
        json.dump(data, file, indent=4)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

store_data = load_data()

# App interface
def main():
    st.title("🔐 Secure Data Storage and Retrieval System")
    st.sidebar.title("📌 Navigation")
    options = ["🏠 Home", "🔑 Login", "📝 Register", "💾 Store Data", "📂 Retrieve Data"]
    choice = st.sidebar.selectbox("Select an option", options)

    # Home
    if choice == "🏠 Home":
        st.subheader("👋 Welcome!")
        st.markdown("""
        This app allows you to securely **store** and **retrieve** sensitive data using encryption.
        - 📝 Register or 🔑 Log in to start
        - 🔒 Data is protected using Fernet encryption
        """)

    # Registration
    elif choice == "📝 Register":
        st.subheader("📝 Register a New Account")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Register"):
            if username in store_data:
                st.error("❌ Username already exists.")
            elif not username or not password:
                st.warning("⚠️ Please fill in both fields.")
            else:
                hashed_password = hash_password(password)
                store_data[username] = {
                    "password": hashed_password,
                    "data": []
                }
                save_data(store_data)
                st.success("✅ Registration successful! You can now log in.")

    # Login
    elif choice == "🔑 Login":
        st.subheader("🔐 User Login")

        if time.time() < st.session_state.lockout_time:
            remaining = int(st.session_state.lockout_time - time.time())
            st.error(f"🚫 Too many failed attempts. Try again in {remaining} seconds.")
            st.stop()

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            user_record = store_data.get(username)
            if user_record and hash_password(password) == user_record["password"]:
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f"✅ Welcome back, {username}!")
            else:
                st.session_state.failed_attempts += 1
                st.error("❌ Invalid credentials.")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("🚫 Too many failed attempts. You are temporarily locked out.")

    # Store Data
    elif choice == "💾 Store Data":
        if st.session_state.authenticated_user is None:
            st.warning("🔐 Please log in to store data.")
        else:
            st.subheader("📥 Store Encrypted Data")
            key = st.text_input("Encryption Key", type="password")
            data = st.text_area("Enter Data to Store")

            if st.button("Encrypt & Save"):
                if key and data:
                    encrypted_data = encrypt_text(data, key)
                    store_data[st.session_state.authenticated_user]["data"].append(encrypted_data)
                    save_data(store_data)
                    st.success("✅ Data encrypted and stored successfully!")
                else:
                    st.warning("⚠️ Please provide both the encryption key and data.")

    # Retrieve Data
    elif choice == "📂 Retrieve Data":
        if st.session_state.authenticated_user is None:
            st.warning("🔐 Please log in to retrieve data.")
        else:
            st.subheader("📤 Retrieve Encrypted Data")
            user_data = store_data.get(st.session_state.authenticated_user, {}).get("data", [])

            if not user_data:
                st.info("ℹ️ No data found for this user.")
            else:
                st.write("🔒 Encrypted Entries:")
                for i, item in enumerate(user_data, start=1):
                    st.code(f"{i}. {item}", language="plaintext")

                selected = st.number_input("Enter data number to decrypt", min_value=1, max_value=len(user_data), step=1)
                passkey = st.text_input("Enter Decryption Key", type="password")

                if st.button("Decrypt"):
                    selected_data = user_data[selected - 1]
                    decrypted = decrypt_text(selected_data, passkey)
                    if decrypted:
                        st.success("🔓 Decrypted Data:")
                        st.write(decrypted)
                    else:
                        st.error("❌ Decryption failed. Check the key and try again.")

if __name__ == "__main__":
    main()
