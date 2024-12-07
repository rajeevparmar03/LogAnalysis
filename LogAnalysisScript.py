import re
import csv
from collections import defaultdict

# Function to extract IP, endpoint, and status from a single log line
def extract_log_details(log_line):
    try:
        ip_match = re.match(r'(\d{1,3}\.){3}\d{1,3}', log_line)
        
        endpoint_match = re.search(r'\"[A-Z]+\s(/[\w\-/\.\?=&]*)\s', log_line)

        status_match = re.search(r'\s(\d{3})(?:\s|$)', log_line)

        ip = ip_match.group(0) if ip_match else None
        endpoint = endpoint_match.group(1) if endpoint_match else None
        status_code = int(status_match.group(1)) if status_match else None

        return ip, endpoint, status_code
    except Exception as error:
        print(f"Unable to parse line: {log_line.strip()}. Error: {error}")
        return None, None, None

# Function to calculate the number of requests per IP address
def calculate_ip_request_counts(log_lines):
    request_counts = defaultdict(int)
    for log_line in log_lines:
        ip, _, _ = extract_log_details(log_line)
        if ip:
            request_counts[ip] += 1
    return request_counts

# Function to find the most accessed endpoint in the log
def get_top_accessed_endpoint(log_lines):
    endpoint_frequency = defaultdict(int)
    for log_line in log_lines:
        _, endpoint, _ = extract_log_details(log_line)
        if endpoint:
            endpoint_frequency[endpoint] += 1
    if endpoint_frequency:
        return max(endpoint_frequency.items(), key=lambda item: item[1])
    return None

# Function to identify suspicious activities based on failed login attempts
def identify_suspicious_ips(log_lines, limit=10, failure_terms=None):
    if failure_terms is None:
        failure_terms = ['401', 'Invalid credentials']
    failed_attempts = defaultdict(int)
    failure_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+).*?"\s401\s.*"(Invalid credentials|Authentication failed)"')
    for log_line in log_lines:
        match = failure_pattern.search(log_line)
        if match:
            ip = match.group(1)
            failed_attempts[ip] += 1
    return {ip: count for ip, count in failed_attempts.items() if count >= limit}

# Function to save analysis results into a CSV file
def export_analysis_to_csv(ip_counts, top_endpoint, flagged_ips):
    try:
        with open("log_analysis_output.csv", mode="w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            
            writer.writerow(["IP Address Analysis"])
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in ip_counts.items():
                writer.writerow([ip, count])

            writer.writerow([])

            writer.writerow(["Most Accessed Endpoint"])
            if top_endpoint:
                writer.writerow([top_endpoint[0], f"{top_endpoint[1]} accesses"])
            else:
                writer.writerow(["No endpoint data found."])

            writer.writerow([])

            writer.writerow(["Suspicious IPs"])
            writer.writerow(["IP Address", "Failed Login Attempts"])
            for ip, count in flagged_ips.items():
                writer.writerow([ip, count])
    except Exception as error:
        print(f"Error saving data to CSV: {error}")

# Main function to process log files and generate reports
def process_log_file(file_path, limit=10):
    try:
        with open(file_path, 'r') as file:
            log_lines = file.readlines()

        # Generate IP request counts
        ip_counts = calculate_ip_request_counts(log_lines)

        # Identify most frequently accessed endpoint
        top_endpoint = get_top_accessed_endpoint(log_lines)

        # Find suspicious IPs
        flagged_ips = identify_suspicious_ips(log_lines, limit)

        # Display results in console
        print("IP Request Counts:")
        for ip, count in ip_counts.items():
            print(f"{ip:<20} {count}")

        print("\nTop Accessed Endpoint:")
        if top_endpoint:
            print(f"{top_endpoint[0]} - {top_endpoint[1]} times")
        else:
            print("No endpoints identified.")

        print("\nSuspicious IPs Detected:")
        for ip, count in flagged_ips.items():
            print(f"{ip:<20} {count}")

        # Save results to a CSV file
        export_analysis_to_csv(ip_counts, top_endpoint, flagged_ips)
        print("Analysis results saved to 'log_analysis_output.csv'.")
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    except Exception as error:
        print(f"An unexpected error occurred: {error}")

# Example usage
if __name__ == "__main__":
    log_file_path = "logfile.txt"  # Replace with your log file name
    process_log_file(log_file_path, limit=3)
