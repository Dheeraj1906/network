import subprocess
import json

def run_nmap_scan(target_ip, scan_type="default", options=None):
    try:
        # Define default scan options
        nmap_commands = {
            "default": ["nmap", "-p", "1-65535", "--open", target_ip],
            "stealth": ["nmap", "-sS", target_ip],
            "service_version": ["nmap", "-sV", target_ip],
            "os_detection": ["nmap", "-O", target_ip],
            "custom": ["nmap"] + (options or []) + [target_ip]
        }

        if scan_type not in nmap_commands:
            raise ValueError("Invalid scan type specified.")

        # Run the selected Nmap command
        command = nmap_commands[scan_type]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            raise Exception(result.stderr)

        # Parse results to extract relevant information
        output_lines = result.stdout.splitlines()
        open_ports = []
        for line in output_lines:
            # Extract open ports from the output
            if "open" in line:
                parts = line.split()
                port_service = {
                    "port": parts[0].split("/")[0],  # Extract the port number
                    "state": parts[1],  # State (e.g., open)
                    "service": parts[2] if len(parts) > 2 else "unknown"  # Service name (if available)
                }
                open_ports.append(port_service)

        # Construct a structured result
        scan_results = {
            "target_ip": target_ip,
            "scan_type": scan_type,
            "open_ports": open_ports,
            "raw_output": result.stdout  # Include raw output for reference
        }

        # Save results to a file (optional)
        with open("nmap_detailed_scan.json", "w") as f:
            json.dump(scan_results, f, indent=4)

        return scan_results
    except Exception as e:
        raise Exception(f"Nmap scan failed: {str(e)}")
