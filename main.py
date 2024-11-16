import os
import hashlib
import magic
import pyfiglet
import requests
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

class AntiVirusApp:
    def __init__(self, master):
        self.master = master
        master.title("AntiVirus")
        master.geometry("400x300")
        master.resizable(False, False)

        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.create_widgets()

    def create_widgets(self):
        # Banner
        banner = pyfiglet.figlet_format("AntiVirus", font="small")
        banner_label = tk.Label(self.master, text=banner, font=("Courier", 8))
        banner_label.pack(pady=10)

        # File selection
        file_frame = ttk.Frame(self.master)
        file_frame.pack(pady=10)

        self.file_path = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=self.file_path, width=40)
        file_entry.grid(row=0, column=0, padx=5)

        browse_button = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        browse_button.grid(row=0, column=1, padx=5)

        # Scan button
        scan_button = ttk.Button(self.master, text="Scan File", command=self.scan_file)
        scan_button.pack(pady=10)

        # Update definitions button
       # update_button = ttk.Button(self.master, text="Update Virus Definitions", command=self.update_virus_definitions)
       # update_button.pack(pady=10)

        # Status
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_label = ttk.Label(self.master, textvariable=self.status_var)
        status_label.pack(pady=10)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path.set(file_path)

    def get_file_hashes(self, file_path):
        with open(file_path, 'rb') as file:
            file_data = file.read()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
        return sha256_hash

    def identify_file_type(self, file_path):
        file_type = magic.from_file(file_path)
        return file_type

    def check_for_virus_signatures(self, file_path):
        file_hash = self.get_file_hashes(file_path)
        virus_signatures = ['f5c34a6757804a619a99a1ba73ba51ba25a158e5ee6e9cc86a2be1292064e415', 'd2097c734fa39a904796dc832946d5c23f400c7a','6af7bb44c8e6e041bf2ee6b7a60d9ab3','2eabe9054cad5152567f0699947a2c5b','6b1d37510f2465cd2931c4814b85f21115dda4c6694667c734142e03235917ae']  # Replace with actual virus signatures

        if file_hash in virus_signatures:
            return True
        else:
            return False

    # def update_virus_definitions(self):
    #     try:
    #         response = requests.get('https://example.com/virus_definitions.txt')
    #         if response.status_code == 200:
    #             virus_definitions = response.text.split('\n')
    #             self.status_var.set("Virus definitions updated successfully.")
    #             messagebox.showinfo("Update Successful", "Virus definitions updated successfully.")
    #         else:
    #             self.status_var.set("Failed to update virus definitions.")
    #             messagebox.showerror("Update Failed", "Failed to update virus definitions.")
    #     except requests.exceptions.RequestException as e:
    #         self.status_var.set(f"Error updating virus definitions: {e}")
    #         messagebox.showerror("Update Error", f"Error updating virus definitions: {e}")

    def scan_file(self):
        file_path = self.file_path.get()
        if not os.path.isfile(file_path):
            self.status_var.set(f"Invalid file path: {file_path}")
            messagebox.showerror("Invalid File", f"Invalid file path: {file_path}")
            return

        file_type = self.identify_file_type(file_path)
        self.status_var.set(f"Scanning file: {file_path} ({file_type})")

        if self.check_for_virus_signatures(file_path):
            self.status_var.set(f"Virus detected in {file_path}!")
            messagebox.showerror("Virus Detected", f"Virus detected in {file_path}!")
        else:
            self.status_var.set(f"{file_path} is clean.")
            messagebox.showinfo("Scan Complete", f"{file_path} is clean.")

def main():
    root = tk.Tk()
    app = AntiVirusApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
    