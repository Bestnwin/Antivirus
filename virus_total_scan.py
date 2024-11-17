import requests
import time
import sys

# Replace with your VirusTotal API key
API_KEY = '583278add49d56c4f02caa49bf19e58e857aa59ba28fc1e437651c45620e4b72'

# Function to upload file to VirusTotal
def upload_file(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": API_KEY
    }
    with open(file_path, 'rb') as file:
        response = requests.post(url, headers=headers, files={"file": file})
    return response

# Function to get file analysis report from VirusTotal
def get_file_report(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)
    return response

# Function to extract file hash from the uploaded file's response
def get_file_hash(response):
    if response.status_code == 200:
        data = response.json()
        return data['data']['id']
    else:
        print("Error uploading file:", response.json())
        return None

# Function to save the analysis report to a text file
def save_report(report_data, output_file):
    with open(output_file, 'w') as f:
        f.write("VirusTotal File Report\n")
        f.write("=" * 50 + "\n")
        f.write(str(report_data))

# Main function
def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py <input_file> <output_report_file>")
        sys.exit(1)
    
    # Input and output file paths from command-line arguments
    input_file_path = sys.argv[1]  # Path to input file (file to scan)
    output_file_path = sys.argv[2]  # Path to output text file for the report

    print(f"Uploading file: {input_file_path}")
    
    # Upload the file
    upload_response = upload_file(input_file_path)
    
    if upload_response.status_code == 200:
        print("File uploaded successfully.")
        
        # Extract the file hash from the response
        file_hash = get_file_hash(upload_response)
        
        if file_hash:
            print("File hash:", file_hash)
            print("Waiting for file analysis to complete...")
            # Wait for the analysis to complete
            time.sleep(15)  # Adjust sleep time if needed

            # Get the file report using the file hash
            report_response = get_file_report(file_hash)

            if report_response.status_code == 200:
                print("File analysis complete. Saving report.")
                # Save the report to the output file
                save_report(report_response.json(), output_file_path)
                print(f"Report saved to: {output_file_path}")
            else:
                print("Error retrieving file report:", report_response.json())
        else:
            print("Error: Unable to get file hash.")
    else:
        print("Error uploading file:", upload_response.json())

# Execute the script
if __name__ == "__main__":
    main()
