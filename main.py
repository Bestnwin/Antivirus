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
        self.master.title("AntiVirus scanner")
        self.master.geometry("600x400")
        self.master.configure(bg="#dbeeff") #background

        self.create_widgets()

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
            insertbackground="#0026ff"  # Cursor color
        )
        file_entry.grid(row=0, column=0, padx=10, pady=5, ipadx=8, ipady=8)

        # Browse button with hover effects
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

        # Scan button
        scan_button = tk.Button(
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

        # Status label
        self.status_var = tk.StringVar()
        self.status_var.set("ready")
        status_label = tk.Label(self.master, textvariable=self.status_var, font=("Helvetica", 14), bg="#dbeeff", fg="#0099ff")
        status_label.pack(pady=20)
        
    def animate_logo(self):
        # Create animated antivirus_logo text
        logo_frames = pyfiglet.figlet_format("AntiVirus", font="big").split("\n")
        self.current_frame = 0

        def update_frame():
            if self.current_frame < len(logo_frames):
                self.canvas.itemconfig(self.logo_text, text="\n".join(logo_frames[: self.current_frame + 1]))
                self.current_frame += 1
                self.master.after(200, update_frame)  # Delay between frames

        update_frame()


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
        with open('hashes.txt', 'r') as file:
            lines = file.readlines()
        virus_signatures = [line.strip() for line in lines]

        #virus_signatures = ['f5c34a6757804a619a99a1ba73ba51ba25a158e5ee6e9cc86a2be1292064e415', 'd2097c734fa39a904796dc832946d5c23f400c7a','6af7bb44c8e6e041bf2ee6b7a60d9ab3','2eabe9054cad5152567f0699947a2c5b','6b1d37510f2465cd2931c4814b85f21115dda4c6694667c734142e03235917ae']  # Replace with actual virus signatures

        def check_and_delete_file(file_path):
            # Check if the file exists
            if os.path.isfile(file_path):
                
                # Create a simple GUI window
                root = tk.Tk()
                root.withdraw()  # Hide the main window

                # Prompt the user for confirmation
                confirm = messagebox.askyesno("Delete File", f"Do you want to delete the file '{file_path}'?")
                
                if confirm:
                    os.remove(file_path)
                    messagebox.showinfo("Deleted", f"File '{file_path}' has been deleted.")
                else:
                    messagebox.showinfo("Canceled", "File deletion canceled.")
            else:
                print(f"File '{file_path}' does not exist.")

        if file_hash in virus_signatures:
            return True
            check_and_delete_file(file_path)
        else:
            return False

    # def update_virus_definitions(self):
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
    