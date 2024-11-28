import subprocess
import json

def create_network_map(subnet):
    try:
        command = ["nmap", "-sn", subnet]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            raise Exception(result.stderr)

        devices = []
        for line in result.stdout.splitlines():
            if "Nmap scan report for" in line:
                devices.append(line.split("for")[-1].strip())

        network_map = {"subnet": subnet, "devices": devices}
        with open("network_map.json", "w") as f:
            json.dump(network_map, f, indent=4)
        return network_map
    except Exception as e:
        raise Exception(f"Network mapping failed: {str(e)}")
