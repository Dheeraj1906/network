from flask import Flask, jsonify, request
import subprocess
import pyshark
import json
from nmap_tools import run_nmap_scan
from packet_capture import capture_packets
from network_mapping import create_network_map
from external_tools import virustotal_scan
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ----------- Network Scanning Routes -----------

def scan_network(target_ip):
    try:
        command = ["nmap", "-p", "1-65535", "--open", target_ip]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            raise Exception(result.stderr)

        open_ports = [line.split("/")[0].strip() for line in result.stdout.splitlines() if "open" in line]

        scan_results = {"target_ip": target_ip, "open_ports": open_ports}
        with open("nmap_scan_results.json", "w") as f:
            json.dump(scan_results, f, indent=4)

        return scan_results
    except Exception as e:
        raise Exception(f"Nmap scan failed: {str(e)}")

@app.route('/scan', methods=['GET'])
def scan_route():
    target_ip = request.args.get('ip')  # Get the target IP from query parameter
    if not target_ip:
        return jsonify({"error": "No IP address provided"}), 400
    try:
        results = scan_network(target_ip)
        return jsonify({
            "message": "Scan completed successfully.",
            "results": results
        }), 200
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/scan_results', methods=['GET'])
def get_scan_results():
    try:
        with open("nmap_scan_results.json", "r") as f:
            results = json.load(f)
        return jsonify(results), 200
    except FileNotFoundError:
        return jsonify({"error": "No scan results found."}), 404
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/clear_scan_results', methods=['DELETE'])
def clear_scan_results():
    try:
        with open("nmap_scan_results.json", "w") as f:
            json.dump({}, f)  # Write an empty JSON object
        return jsonify({"message": "Scan results cleared successfully."}), 200
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/detailed_scan', methods=['GET'])
def detailed_scan():
    target_ip = request.args.get('ip')
    scan_type = request.args.get('type', 'default')
    custom_options = request.args.getlist('options')
    if not target_ip:
        return jsonify({"error": "No target IP provided"}), 400
    try:
        results = run_nmap_scan(target_ip, scan_type, custom_options)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

# ----------- Packet Capturing Routes -----------


@app.route('/capture', methods=['GET'])
def capture_route():
    interface = request.args.get('interface', 'en0')  # Default to 'en0' if not provided
    packet_count = int(request.args.get('count', 5))  # Default to 5 packets if not provided
    try:
        packet_results = capture_packets(interface, packet_count)
        with open('packet_analysis.json', 'w') as f:
            json.dump(packet_results, f, indent=4)

        return jsonify({
            "message": f"Captured {packet_count} packets on interface {interface}.",
            "results": packet_results
        }), 200
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/capture_results', methods=['GET'])
def get_capture_results():
    try:
        with open('packet_analysis.json', 'r') as f:
            packet_results = json.load(f)
        return jsonify(packet_results), 200
    except FileNotFoundError:
        return jsonify({"error": "No packet analysis file found."}), 404
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/clear_capture_results', methods=['DELETE'])
def clear_capture_results():
    try:
        with open('packet_analysis.json', "w") as f:
            json.dump([], f)  # Write an empty list to clear the file
        return jsonify({"message": "Packet analysis data cleared successfully."}), 200
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/filtered_capture', methods=['GET'])
def filtered_capture_route():
    interface = request.args.get('interface', 'en0')
    packet_count = int(request.args.get('count', 5))
    filters = request.args.get('filters', None)
    try:
        packet_results = capture_packets(interface, packet_count, filters)
        with open('filtered_packet_analysis.json', 'w') as f:
            json.dump(packet_results, f, indent=4)
        return jsonify({
            "message": f"Captured {packet_count} packets on interface {interface} with filter '{filters}'.",
            "results": packet_results
        }), 200
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

#this is comment
@app.route('/network_map', methods=['GET'])
def network_map_route():
    subnet = request.args.get('subnet', '192.168.1.0/24')
    try:
        network_map = create_network_map(subnet)
        return jsonify(network_map), 200
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

# ----------- Service Status -----------


# @app.route('/virustotal_scan', methods=['GET'])
# def virustotal_scan_route():
#     ip = request.args.get('ip')
#     api_key = request.args.get('api_key')
#     if not ip or not api_key:
#         return jsonify({"error": "IP and API key are required"}), 400
#     try:
#         results = virustotal_scan(ip, api_key)
#         return jsonify(results), 200
#     except Exception as e:
#         return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/status', methods=['GET'])
def service_status():
    return jsonify({"status": "Service is running", "version": "1.0.0"}), 200

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5001)
