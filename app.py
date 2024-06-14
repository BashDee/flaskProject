from flask import Flask, render_template, request, jsonify
import re
import string
import itertools
import requests

app = Flask(__name__)


# Function to load common passwords from a URL with error handling and fallback to local file
def load_common_passwords(
        url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
        local_file="local_passwords.txt", timeout=10):
    try:
        response = requests.get(url, timeout=timeout)
        if response.status_code == 200:
            return response.text.splitlines()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching the dictionary: {e}")

    # Fallback to local file
    try:
        with open(local_file, 'r') as file:
            return file.read().splitlines()
    except Exception as e:
        print(f"Error loading local dictionary file: {e}")
        return None


# Dictionary attack function
def dictionary_attack(password, common_passwords):
    return password in common_passwords


# Brute force attack function
def brute_force_attack(password, max_length=4):
    characters = string.ascii_letters + string.digits + string.punctuation
    for length in range(1, max_length + 1):
        for attempt in itertools.product(characters, repeat=length):
            if "".join(attempt) == password:
                return True
    return False


# Password strength evaluation function
def password_strength(password):
    # Traditional strength criteria
    length_criteria = len(password) >= 8
    lowercase_criteria = any(c.islower() for c in password)
    uppercase_criteria = any(c.isupper() for c in password)
    digit_criteria = any(c.isdigit() for c in password)
    special_criteria = any(c in string.punctuation for c in password)

    strength = sum([length_criteria, lowercase_criteria, uppercase_criteria, digit_criteria, special_criteria])

    if strength == 5:
        return "Very Strong"
    elif strength == 4:
        return "Strong"
    elif strength == 3:
        return "Moderate"
    elif strength == 2:
        return "Weak"
    else:
        return "Very Weak"


# Load common passwords at startup
common_passwords = load_common_passwords()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/check_strength', methods=['POST'])
def check_strength():
    password = request.form['password']
    strength = password_strength(password)
    return jsonify({"strength": strength})


@app.route('/dictionary_attack', methods=['POST'])
def check_dictionary_attack():
    password = request.form['password']
    if common_passwords is None:
        return jsonify({"result": "Dictionary not available, unable to check further"})

    if dictionary_attack(password, common_passwords):
        return jsonify({"result": "Dictionary Attack Successful: Password Not Secure"})
    else:
        return jsonify({"result": "Dictionary Attack Failed: Password Not Found in Dictionary"})


@app.route('/brute_force_attack', methods=['POST'])
def check_brute_force_attack():
    password = request.form['password']
    if len(password) <= 5 and brute_force_attack(password):
        return jsonify({"result": "Brute Force Attack Successful: Password Not Secure"})
    else:
        return jsonify({"result": "Brute Force Attack Failed"})


if __name__ == '__main__':
    app.run(debug=True)
