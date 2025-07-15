import json

# Load the report.json file
def load_report(file_path):
    try:
        with open(file_path, 'r') as file:
            report_data = json.load(file)

            # Check if the data is wrapped in a dictionary and contains a 'dependencies' key
            if isinstance(report_data, dict):
                print("Data is in dictionary format.")
                if 'dependencies' in report_data:
                    return report_data['dependencies']
                else:
                    print("Warning: 'dependencies' key not found in the data.")
                    return []
            else:
                print("Warning: The data is not in dictionary format as expected!")
                return []

    except Exception as e:
        print(f"Error loading file: {e}")
        return None

# Process the vulnerabilities and format them as required
def process_vulnerabilities(report_data):
    vulnerabilities = {}

    # Loop through the dependencies and vulnerabilities
    for item in report_data:
        if isinstance(item, dict):  # Ensure the item is a dictionary
            vuln_name = item.get('vulnerability_name', 'Unknown')
            severity = item.get('severity', 'unknown').lower()  # Default to 'unknown' if no severity
            file_names = item.get('file_names', [])

            if vuln_name not in vulnerabilities:
                vulnerabilities[vuln_name] = {
                    'vulnerability_name': vuln_name,
                    'severity': severity,
                    'file_names': set()  # Store file names in a set to avoid duplicates
                }

            vulnerabilities[vuln_name]['file_names'].update(file_names)

    # Convert sets to lists and sort by severity (high first)
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'unknown': 4}
    for vuln in vulnerabilities.values():
        vuln['file_names'] = list(vuln['file_names'])  # Convert set to list

    sorted_vulnerabilities = sorted(vulnerabilities.values(), key=lambda x: severity_order.get(x['severity'], 4))

    return sorted_vulnerabilities

# Write the output to a JSON file
def write_output(vulnerabilities, output_file):
    try:
        with open(output_file, 'w') as file:
            json.dump(vulnerabilities, file, indent=4)
    except Exception as e:
        print(f"Error writing file: {e}")

# Main function to load, process and save the results
def main(input_file, output_file):
    report_data = load_report(input_file)

    if report_data:
        vulnerabilities = process_vulnerabilities(report_data)
        write_output(vulnerabilities, output_file)
        print("Vulnerability report processed and saved.")
    else:
        print("No valid report data to process.")

# Run the script
if __name__ == "__main__":
    input_file = 'report.json'  # Path to your input report.json (second report)
    output_file = 'processed_report.json'  # Path to save the output
    main(input_file, output_file)
