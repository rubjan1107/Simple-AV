import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import time
import stat
import re

infected_files = []  # Store infected files

# Define virus signatures and suspicious patterns globally
virus_signatures = [
    # EICAR Test File (for safe testing)
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    
    # Windows PE Executable Header
    b"\x4D\x5A",  # "MZ" signature for PE files

    # Shellcode patterns
    b"\xE8\x00\x00\x00\x00\x5B\x81\xEB",  # Common process injection shellcode
    b"\xC7\x45\xFC\x00\x00\x00\x00",      # Heap spraying in exploits

    # Python-based keyloggers (looking for imports related to keylogging)
    b"import pynput.keyboard",  # Python pynput keylogger library
    b"from pynput.keyboard",    # Alternative keylogger import

    # Command execution patterns (often used by malware)
    b"cmd.exe /c",                        # Command execution
    b"C:\\Windows\\System32\\cmd.exe",    # Path to cmd.exe
    b"powershell.exe",                    # PowerShell execution
    
    # Backdoor or RAT (Remote Access Trojan) indicators
    b"WSAStartup",                        # Network API used in backdoors
    b"bind",                              # Port binding by backdoors
    b"connect",                           # Network connection function
    
    # Keylogger patterns
    b"GetAsyncKeyState",                  # Keystroke detection
    b"SetWindowsHookExA",                 # Hooking input devices
    
    # Ransomware signatures
    b"Encrypted by",                      # Common in ransom note text
    b"AES-256-ENC",                       # Encryption algorithm signature
    b".locked",                           # Ransomware file extension
    b"!!!READ_ME!!!.txt"                  # Ransom note file name
]

suspicious_patterns = [
    b"shell32.dll",
    b"kernel32.dll",
    b"CreateProcess",
    b"cmd.exe",
    b"regsvr32.exe",
    b"socket",        # Network function used for reverse shells
    b"bind",          # Network binding
    b"connect",       # Connecting to remote
    b"exec",          # Command execution in Python
    b"subprocess"     # Command execution in Python
]

# Function to select files or directories
def select():
    """Select file or directory based on the mode."""
    clear_results()  # Clear results from the previous scan
    global infected_files
    infected_files.clear()  # Clear any previous infected files
    
    if scan_mode.get() == "file":
        file_path = filedialog.askopenfilename()  # Prompt for a single file
        if file_path:
            file_path = os.path.normpath(file_path)  # Normalize the path for compatibility
            scan_file(file_path)  # Start scanning the selected file
        else:
            result_text.insert(tk.END, "No file selected.\n")
    else:
        directory_path = filedialog.askdirectory()  # Prompt for a directory
        if directory_path:
            directory_path = os.path.normpath(directory_path)  # Normalize the path for compatibility
            scan_directory(directory_path)  # Start scanning the selected directory
        else:
            result_text.insert(tk.END, "No directory selected.\n")
    
    # After scanning is complete (either a file or folder), prompt the user to remove infected files
    if infected_files:
        prompt_file_selection()  # Show checkbox prompt after scanning

# Function to clear the results
def clear_results():
    """Clear the result text area before a new scan and reset the progress bar."""
    result_text.delete(1.0, tk.END)
    progress_var.set(0)  # Reset progress bar

# Main function to scan a file for signatures and patterns
def scan_file(file_path):
    """Scans a single file for virus signatures, suspicious patterns, and heuristic analysis."""
    if not os.path.isfile(file_path):
        result_text.insert(tk.END, f"{file_path} is not a valid file.\n")
        return

    try:
        virus_found = False
        heuristic_alert = False
        severity_score = 0

        # Open the file in binary mode for signature scanning
        with open(file_path, "rb") as f:
            result_text.insert(tk.END, f"Scanning file: {file_path}\n")
            
            chunk_size = 4096
            
            while chunk := f.read(chunk_size):
                # Check for virus signatures
                for signature in virus_signatures:
                    if signature in chunk:
                        result_text.insert(tk.END, f"Virus signature found: {signature.decode('latin1', 'ignore')}\n")
                        virus_found = True
                        severity_score += 50
                        break  # Exit loop once a virus is found
                
                # Check for suspicious patterns
                for pattern in suspicious_patterns:
                    if pattern in chunk:
                        result_text.insert(tk.END, f"Suspicious pattern found: {pattern.decode('latin1', 'ignore')}\n")
                        heuristic_alert = True
                        severity_score += 25

        # Perform heuristic analysis: detect potential keylogging or malicious behavior
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            if re.search(r"(pynput|keyboard|on_press)", content):
                result_text.insert(tk.END, f"Keylogger behavior detected in {file_path} (pynput usage).\n")
                heuristic_alert = True
                severity_score += 50

            # Check for network connection attempts in Python code
            if re.search(r"(socket|bind|connect)", content):
                result_text.insert(tk.END, f"Suspicious network activity detected in {file_path} (socket usage).\n")
                heuristic_alert = True
                severity_score += 50

            # Detect subprocess execution commands in Python
            if re.search(r"(subprocess|os.system|exec)", content):
                result_text.insert(tk.END, f"Command execution detected in {file_path} (subprocess/os.system usage).\n")
                heuristic_alert = True
                severity_score += 50

        # If a virus or heuristic issue is found, add it to the infected files list
        if virus_found or heuristic_alert:
            display_heuristic_analysis(file_path, severity_score)
            infected_files.append(file_path)  # Add the infected file to the list
        else:
            result_text.insert(tk.END, f"No issues detected in {file_path}\n")

    except OSError as e:
        result_text.insert(tk.END, f"Error scanning file: {e}\n")

# Function to scan all files in a directory recursively
def scan_directory(directory_path):
    """Scans all files and subfolders in a directory recursively."""
    files = []
    
    # Recursively gather all files from the directory and its subfolders
    for root, dirs, filenames in os.walk(directory_path):
        for file in filenames:
            file_path = os.path.join(root, file)
            file_path = os.path.normpath(file_path)  # Normalize paths
            if os.path.isfile(file_path):  # Ensure it's a regular file
                files.append(file_path)
    
    total_files = len(files)
    
    if total_files == 0:
        result_text.insert(tk.END, "No files found in the selected directory.\n")
        return

    # Scan each file in the directory
    for idx, file in enumerate(files, 1):
        scan_file(file)  # Scan each file
        update_progress(idx, total_files)  # Update progress bar after each file

# Display heuristic analysis with color-coded risk levels
def display_heuristic_analysis(file_path, severity_score):
    """Displays heuristic analysis with color-coded risk levels and severity percentage."""
    severity_percentage = severity_score if severity_score <= 100 else 100  # Cap severity at 100%
    
    if severity_percentage >= 75:
        severity_level = "High Risk"
        color = "red"
    elif 50 <= severity_percentage < 75:
        severity_level = "Moderate Risk"
        color = "orange"
    else:
        severity_level = "Low Risk"
        color = "green"
    
    # Insert colored result based on severity and include severity percentage
    result_text.insert(tk.END, f"Heuristic Analysis for {file_path}: {severity_level} ({severity_percentage}% severity)\n")
    result_text.tag_add(severity_level, f"{float(result_text.index('end')) - 2} linestart", "end")
    result_text.tag_config(severity_level, foreground=color)

# Function to prompt the user with a list of infected files and checkboxes
def prompt_file_selection():
    """Opens a new window with checkboxes for the user to select which infected files to delete."""
    selection_window = tk.Toplevel(root)
    selection_window.title("Select Infected Files to Remove")
    selection_window.geometry("500x1000")

    tk.Label(selection_window, text="Select files to delete:", font=("Arial", 12)).pack(pady=10)

    # Dictionary to store the checkbox states
    file_vars = {}

    # Create a checkbox for each infected file
    for file_path in infected_files:
        var = tk.IntVar()
        file_vars[file_path] = var
        chk = tk.Checkbutton(selection_window, text=file_path, variable=var, wraplength=300, anchor="w", justify="left")
        chk.pack(fill="x", padx=10, pady=5)

    # Button to confirm file deletion
    delete_button = tk.Button(selection_window, text="Delete Selected Files", command=lambda: delete_selected_files(file_vars, selection_window), bg="red", fg="white")
    delete_button.pack(pady=10)

# Function to delete selected files based on checkbox selection
def delete_selected_files(file_vars, window):
    """Deletes files that the user has selected via checkboxes."""
    for file_path, var in file_vars.items():
        if var.get() == 1:  # If the checkbox is checked
            try:
                os.remove(file_path)
                result_text.insert(tk.END, f"File {file_path} deleted successfully.\n")
            except OSError as e:
                result_text.insert(tk.END, f"Error deleting file {file_path}: {e}\n")
        else:
            result_text.insert(tk.END, f"File {file_path} was not deleted.\n")

    window.destroy()  # Close the selection window after deleting files

# Stop the scan and update the result
def stop_scan():
    """Stops the scan and updates the result."""
    result_text.insert(tk.END, "Scan stopped.\n")

# Quit the application
def quit_app():
    """Quits the application."""
    result_text.insert(tk.END, "Exiting the application.\n")
    root.quit()

# Update the progress bar during scanning
def update_progress(current, total):
    """Updates the progress bar during scanning."""
    progress_var.set(current / total * 100)
    progress_bar.update()

# Initialize Tkinter app
root = tk.Tk()
root.title("Antivirus Scanner")
root.geometry("1000x650")

scan_mode = tk.StringVar(value="file")

# Header Frame
header_frame = tk.Frame(root, bg="#2c3e50")
header_frame.pack(fill="x")
label = tk.Label(header_frame, text="Antivirus Scanner", font=("Helvetica", 18), bg="#2c3e50", fg="white")
label.pack(pady=10)

# Mode Selection
mode_frame = tk.Frame(root, bg="#f0f0f0")
mode_frame.pack(fill="x", pady=5)

tk.Radiobutton(mode_frame, text="Scan File", variable=scan_mode, value="file", font=("Arial", 12), bg="#f0f0f0").pack(side=tk.LEFT, padx=10)
tk.Radiobutton(mode_frame, text="Scan Directory", variable=scan_mode, value="directory", font=("Arial", 12), bg="#f0f0f0").pack(side=tk.LEFT, padx=10)

# Progress bar
progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100)
progress_bar.pack(fill="x", padx=10, pady=10)

# Buttons Frame
button_frame = tk.Frame(root, bg="#f0f0f0")
button_frame.pack(fill="x", pady=10)

scan_button = tk.Button(button_frame, text="Start Scan", command=select, font=("Arial", 12), bg="#3498db", fg="white")
scan_button.grid(row=0, column=0, padx=10, pady=10)

stop_button = tk.Button(button_frame, text="Stop Scan", command=stop_scan, font=("Arial", 12), bg="#f39c12", fg="white")
stop_button.grid(row=0, column=1, padx=10, pady=10)

quit_button = tk.Button(button_frame, text="Quit", command=quit_app, font=("Arial", 12), bg="#e74c3c", fg="white")
quit_button.grid(row=0, column=2, padx=10, pady=10)

# Result display
result_text = tk.Text(root, height=15, width=70, font=("Arial", 10), wrap="word", bg="#ecf0f1")
result_text.pack(padx=10, pady=10)

root.mainloop()
