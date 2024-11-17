import time
import hashlib
import requests
import json

API_KEY = "583278add49d56c4f02caa49bf19e58e857aa59ba28fc1e437651c45620e4b72"  # Replace with your VirusTotal API key

def calculate_file_hash(file_path):
    hash_function = hashlib.sha256()
    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            hash_function.update(chunk)
    return hash_function.hexdigest()

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

def get_analysis_status(file_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.json()}

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
