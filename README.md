# AntiVirus Scanner

A Python-based AntiVirus Scanner with a simple and user-friendly interface. This tool allows users to scan files for potential threats using VirusTotal API integration, hash-based detection, and dynamic file type identification.

## Features
- **File Scanning**: Scan local files for potential threats.
- **VirusTotal Integration**: Analyze files using VirusTotal's multi-engine database.
- **GUI Interface**: Modern, intuitive interface built with `Tkinter`.
- **Threat Detection and Management**: Alerts for infected files and provides an option to delete them.
- **Detailed Reports**: Save analysis results in JSON format for further review.

## Technologies Used
- **Python Libraries**:
  - `os`
  - `hashlib`
  - `magic`
  - `requests`
  - `pandas`
  - `Pillow`
  - `tkinter`
- **API Integration**: [VirusTotal API](https://www.virustotal.com/)


Install dependencies:
bash
Copy code
pip install -r requirements.txt
Add your VirusTotal API key:
Open the script and replace API_KEY = "ur api_key" with your actual API key.
Usage
Run the Application
Launch the application:
bash
Copy code
python antivirus_scanner.py
Use the GUI:
Browse to select a file.
Click Scan File to start scanning.
View scan results on-screen and in reports.
Output
JSON Report: Saved in the output/ directory.
Console Output: Summarized analysis in tabular format.
File Details
Core Files
File Name	Description
antivirus_scanner.py	Main script for scanning files and GUI logic.
hashes.txt	Stores virus signature hashes for local detection.
requirements.txt	Lists dependencies needed for the project.
output/	Directory where scan reports are saved.
Key Features
VirusTotal Integration
Automatically uploads files to VirusTotal for analysis.
Retrieves detailed reports on file scans.
Interactive GUI
Dynamic Buttons: Hover effects and enhanced interactivity.
Customizable Design: Colors, fonts, and a logo for better user experience.
Security Measures
Local Signature Matching: Compares files against known malware hashes.
File Deletion: Deletes infected files after confirmation.
Contributing
Steps to Contribute:
Fork the repository.
Create a feature branch:
bash
Copy code
git checkout -b feature-name
Commit your changes:
bash
Copy code
git commit -m "Add feature description"
Push your branch:
bash
Copy code
git push origin feature-name
Open a pull request on GitHub.
License
This project is licensed under the MIT License. See the LICENSE file for details.
