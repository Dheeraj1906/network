import subprocess
import json
import socket

def create_network_map(subnet):
    try:
        command = ["nmap", "-sn", subnet]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            raise Exception(result.stderr)

        devices = []
        for line in result.stdout.splitlines():
            if "Nmap scan report for" in line:
                device_ip = line.split("for")[-1].strip()
                try:
                    # Attempt to resolve the hostname for the IP address
                    device_name = socket.gethostbyaddr(device_ip)[0]
                except socket.herror:
                    # If hostname resolution fails, use "N/A"
                    device_name = "N/A"
                devices.append({"ip": device_ip, "name": device_name})

        network_map = {"subnet": subnet, "devices": devices}
        with open("network_map.json", "w") as f:
            json.dump(network_map, f, indent=4)

        return network_map
    except Exception as e:
        raise Exception(f"Network mapping failed: {str(e)}")
