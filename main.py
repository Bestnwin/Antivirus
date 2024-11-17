import os
import hashlib
import magic
import pyfiglet
import requests
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import time
import hashlib
import requests
import json
import pandas as pd


# Your VirusTotal API key
API_KEY = "583278add49d56c4f02caa49bf19e58e857aa59ba28fc1e437651c45620e4b72"  # Replace with your API key

class AntiVirusApp:
    def __init__(self, master):
        self.master = master
        self.master.title("AntiVirus scanner")
        self.master.geometry("600x400")
        self.master.configure(bg="#dbeeff") #background

        self.create_widgets()
        self.set_window_icon("C:\Antivirus\logo1.png")

    
    def set_window_icon(self, image_path):
        img = Image.open(image_path)
        photo = ImageTk.PhotoImage(img)
        self.master.iconphoto(True, photo)  



    def create_widgets(self):
        
        antivirus_logo = "Antivirus"
        antivirus_logo_label = tk.Label(self.master, text=antivirus_logo, font=("Helvetica", 48, "bold"), bg="#dbeeff", fg="#0026ff")
        antivirus_logo_label.pack(pady=20)

        # File selection frame
        file_frame = ttk.Frame(self.master)
        file_frame.pack(pady=20)

        self.file_path = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=self.file_path, font=("Helvetica", 12), width=30)
        file_entry.grid(row=0, column=0, padx=5)

        browse_button = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        browse_button.grid(row=0, column=1, padx=5)

        file_entry = tk.Entry(
            file_frame,
            textvariable=self.file_path,
            font=("Helvetica", 14),
            width=40,
            bg="white",
            fg="#555555",
            relief="flat",
            insertbackground="#0026ff" 
        )
        file_entry.grid(row=0, column=0, padx=10, pady=5, ipadx=8, ipady=8)

        #button
        browse_button = tk.Button(
            file_frame,
            text="Browse",
            font=("Helvetica", 12, "bold"),
            bg="#0099ff",
            fg="white",
            activebackground="#005bb5",
            activeforeground="white",
            relief="flat",
            command=self.browse_file,
        )
        browse_button.grid(row=0, column=1, padx=5, ipadx=15, ipady=5)

        def on_browse_hover(event):
            browse_button.config(bg="#007acc")

        def on_browse_leave(event):
            browse_button.config(bg="#0099ff")

        browse_button.bind("<Enter>", on_browse_hover)
        browse_button.bind("<Leave>", on_browse_leave)

        scan_button = tk.Button(    #scan button 
            self.master,
            text="Scan File",
            font=("Helvetica", 16, "bold"),
            bg="#0099ff",
            fg="white",
            activebackground="#005bb5",
            activeforeground="white",
            relief="flat",
            width=15,
            height=2,
            command=self.scan_file,
        )
        scan_button.pack(pady=20)
        

        #hover button 
        def scan_hover(event):      
            scan_button.config(bg="blue")

        def on_scan_leave(event):
            scan_button.config(bg="#0099ff")

        scan_button.bind("<Enter>", scan_hover)
        scan_button.bind("<Leave>", on_scan_leave)



        self.status_var = tk.StringVar()
        self.status_var.set("ready")
        status_label = tk.Label(self.master, textvariable=self.status_var, font=("Helvetica", 14), bg="#dbeeff", fg="#0099ff")
        status_label.pack(pady=20)
        
    def animate_logo(self):
        logo_frames = pyfiglet.figlet_format("AntiVirus", font="big").split("\n")
        self.current_frame = 0

        def update_frame():
            if self.current_frame < len(logo_frames):
                self.canvas.itemconfig(self.logo_text, text="\n".join(logo_frames[: self.current_frame + 1]))
                self.current_frame += 1
                self.master.after(200, update_frame) 

        update_frame()


    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path.set(file_path)

    def get_file_hashes(self, file_path):
        with open(file_path, 'rb') as file:
            file_data = file.read()
            hash = hashlib.sha256(file_data).hexdigest()    #hash is sha256
        return hash

    def identify_file_type(self, file_path):
        file_type = magic.from_file(file_path)
        return file_type


        




    def check_for_virus_signatures(self, file_path):
        def check_and_delete_file(file_path):
                # Check if the file exists
                if os.path.isfile(file_path):
                    # Create the tkinter root window, but keep it hidden
                    root = tk.Tk()
                    root.withdraw()  # Hide the main window

                    # Ask the user for confirmation to delete the file
                    confirm = messagebox.askyesno("Delete File", f"Do you want to delete the file '{file_path}'?")
                    
                    if confirm:
                        # Delete the file if the user confirms
                        os.remove(file_path)
                        messagebox.showinfo("Deleted", f"File '{file_path}' has been deleted.")
                    else:
                        messagebox.showinfo("Canceled", "File deletion canceled.")
                else:
                    print(f"File '{file_path}' does not exist.")

#virustotal
    #api work-

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
    



        def virus_total_report(file_path,file_hash):
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
                return report

        


        file_hash = self.get_file_hashes(file_path)
        with open('hashes.txt', 'r') as file:        #hash input 
            lines = file.readlines()
        virus_signatures = [line.strip() for line in lines]
        report=virus_total_report(file_path,file_hash)
        # Extracting the `last_analysis_results`
        results = report["data"]["attributes"]["last_analysis_results"]

        # Converting to a pandas DataFrame for tabular representation
        df = pd.DataFrame(results).T  # .T to transpose since we want keys as rows

        # File paths
        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        json_file_path = os.path.join(output_dir, "formatted_report.json")
        table_file_path = os.path.join(output_dir, "last_analysis_results.txt")

        # Save full JSON data in a formatted JSON file
        with open(json_file_path, "w") as json_file:
            json.dump(report, json_file, indent=4)

        # Save the table to a text file
        with open(table_file_path, "w") as table_file:
            table_file.write(df.to_string(index=True))

        # Display the table in Python
        print("Analysis Results Table:")
        print(df)

        # Delete the table file after displaying it
        os.remove(table_file_path)
        print(f"Table file '{table_file_path}' deleted after displaying.")

        # The JSON file is not deleted
        print(f"Formatted JSON saved to {json_file_path}")
        
        def is_detected_from_report(report):
            # Iterate through the engines in the 'last_analysis_results' section
            for engine in report.get('data', {}).get('last_analysis_results', {}).values():
                # Check if the 'category' is 'detected'
                if engine.get('category') == 'detected':
                    return True
            return False


        if file_hash in virus_signatures or is_detected_from_report(report):       #check if it is clean or not
            return True

        else:
            return False


    def scan_file(self):
        file_path = self.file_path.get()
        if not os.path.isfile(file_path):                              #check file path
            self.status_var.set(f"Invalid file path: {file_path}")
            messagebox.showerror("Invalid File", f"Invalid file path: {file_path}")
            return

        file_type = self.identify_file_type(file_path)                    
        self.status_var.set(f"Scanning file: {file_path} ({file_type})")
        check=self.check_for_virus_signatures(file_path)

        if check:                                  #give pop up wether it is clean or not
            self.status_var.set(f"Virus detected in {file_path}!")
            messagebox.showerror("Virus Detected", f"Virus detected in {file_path}!")
            check_and_delete_file(file_path)
        else:
            self.status_var.set(f"{file_path} is clean.")
            messagebox.showinfo("Scan Complete", f"{file_path} is clean.")
            

def main():
    root = tk.Tk()
    app = AntiVirusApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
    