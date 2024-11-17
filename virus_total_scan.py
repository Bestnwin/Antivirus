import time
import hashlib
import requests
import json

# Your VirusTotal API key
API_KEY = "583278add49d56c4f02caa49bf19e58e857aa59ba28fc1e437651c45620e4b72"  # Replace with your API key

# Calculate the SHA-256 hash of a file
def calculate_file_hash(file_path):
    hash_function = hashlib.sha256()
    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            hash_function.update(chunk)
    return hash_function.hexdigest()

# Upload a file to VirusTotal
def upload_file_to_virustotal(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": API_KEY}
    with open(file_path, "rb") as file:
        files = {"file": file}
        response = requests.post(url, headers=headers, files=files)

    if response.status_code == 200:
        return response.json()["data"]["id"]  # File ID for further analysis
    else:
        return {"error": response.json()}

# Get the analysis status of a file
def get_analysis_status(file_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.json()}

# Get the file report from VirusTotal using the hash
def get_file_report(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return {"error": "File not found in VirusTotal database."}
    else:
        return {"error": f"Failed to retrieve report. Status code: {response.status_code}", "details": response.json()}

def write_report_to_file(report, file_name="report.json"):
    try:
        with open(file_name, "w") as report_file:
            json.dump(report, report_file, indent=4)
        print(f"Report successfully saved to {file_name}")
    except Exception as e:
        print(f"Failed to save the report: {e}")

# Main function
def main():
    file_path = r"c:\Users\akshi\Downloads\bestnwin_logo.jpg"  # Replace with your file path

    # Step 1: Calculate the file hash
    print(f"Calculating SHA-256 hash for file: {file_path}")
    file_hash = calculate_file_hash(file_path)
    print(f"SHA-256 Hash: {file_hash}")

    # Step 2: Upload the file to VirusTotal
    print("Uploading file to VirusTotal...")
    file_id = upload_file_to_virustotal(file_path)
    if isinstance(file_id, dict) and "error" in file_id:
        print(f"Error during file upload: {file_id['error']}")
        return
    print(f"File uploaded successfully. File ID: {file_id}")

    # Step 3: Wait for the analysis to complete
    print("Waiting for analysis to complete...")
    while True:
        analysis_status = get_analysis_status(file_id)
        if isinstance(analysis_status, dict) and "error" in analysis_status:
            print(f"Error checking analysis status: {analysis_status['error']}")
            return

        status = analysis_status["data"]["attributes"]["status"]
        if status == "completed":
            print("Analysis completed.")
            break
        else:
            print("Analysis in progress... Retrying in 10 seconds.")
            time.sleep(10)

    # Step 4: Retrieve the file report using the hash
    print("Fetching the file report...")
    report = get_file_report(file_hash)
    if isinstance(report, dict) and "error" in report:
        print(f"Error fetching file report: {report['error']}")
    else:
        print("File Analysis Report:")
        write_report_to_file(report)


# Run the script
if __name__ == "__main__":
    main()