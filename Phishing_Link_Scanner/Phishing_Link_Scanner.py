import tkinter as tk
from tkinter import messagebox
import requests
import validators
import re
from datetime import datetime

# --- Phishing Analysis Functions ---

def is_valid_url(url):
    return validators.url(url)

def fetch_page(url):
    try:
        response = requests.get(url, timeout=10)
        return response.text
    except requests.exceptions.RequestException:
        return None

def analyze_url(url):
    # Check for IP address in domain
    ip_pattern = r"https?://(?:\d{1,3}\.){3}\d{1,3}"
    if re.match(ip_pattern, url):
        return ("Looks Suspicious", "Contains IP address in domain.", "red")
    # Check for too many hyphens
    domain = re.sub(r"https?://", "", url).split("/")[0]
    if domain.count('-') > 3:
        return ("Looks Suspicious", "Domain contains too many hyphens.", "red")
    # Check for strange TLDs
    tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
    if any(domain.endswith(tld) for tld in tlds):
        return ("Looks Suspicious", f"Domain uses suspicious TLD ({', '.join(tlds)}).", "red")
    # Check for HTTPS
    if not url.startswith("https://"):
        return ("Looks Suspicious", "URL does not use HTTPS.", "red")
    # If all checks pass
    return ("Safe-looking URL", "No immediate phishing indicators found.", "green")

def log_scan(url, result, reason):
    with open("scan_log.txt", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {url} - {result}: {reason}\n")

# --- Tkinter UI ---

def scan_url():
    url = url_entry.get().strip()
    if not url:
        result_label.config(text="Please enter a URL.", fg="#e74c3c")
        return
    if not is_valid_url(url):
        result_label.config(text="Invalid Link: URL format is incorrect.", fg="#e74c3c")
        log_scan(url, "Invalid Link", "URL format is incorrect.")
        return
    html = fetch_page(url)
    if html is None:
        result_label.config(text="Invalid Link: Could not fetch the page.", fg="#e74c3c")
        log_scan(url, "Invalid Link", "Could not fetch the page.")
        return
    result, reason, color = analyze_url(url)
    color_map = {"red": "#e74c3c", "green": "#27ae60"}
    result_label.config(text=f"{result}: {reason}", fg=color_map.get(color, color))
    log_scan(url, result, reason)

def clear_fields():
    url_entry.delete(0, tk.END)
    result_label.config(text="")

root = tk.Tk()
root.title("Phishing URL Scanner")
root.geometry("600x350")
root.resizable(False, False)
root.configure(bg="#f0f4f8")

frame = tk.Frame(root, padx=30, pady=30, bg="#ffffff", bd=2, relief="groove")
frame.place(relx=0.5, rely=0.5, anchor="center")

title_label = tk.Label(frame, text="Phishing URL Scanner", font=("Segoe UI", 24, "bold"), bg="#ffffff", fg="#2d3436")
title_label.pack(pady=(0, 18))

url_entry = tk.Entry(frame, width=45, font=("Segoe UI", 14), bd=2, relief="solid", highlightthickness=1, highlightbackground="#b2bec3")
url_entry.pack(pady=10, ipady=6)
url_entry.insert(0, "")

button_frame = tk.Frame(frame, bg="#ffffff")
button_frame.pack(pady=(10, 0))

scan_btn = tk.Button(button_frame, text="Scan", width=14, font=("Segoe UI", 12, "bold"), bg="#0984e3", fg="#fff", activebackground="#74b9ff", activeforeground="#2d3436", bd=0, cursor="hand2", command=scan_url)
scan_btn.grid(row=0, column=0, padx=8)

clear_btn = tk.Button(button_frame, text="Clear", width=14, font=("Segoe UI", 12, "bold"), bg="#636e72", fg="#fff", activebackground="#b2bec3", activeforeground="#2d3436", bd=0, cursor="hand2", command=clear_fields)
clear_btn.grid(row=0, column=1, padx=8)

result_label = tk.Label(frame, text="", font=("Segoe UI", 14, "bold"), bg="#ffffff")
result_label.pack(pady=18)

root.mainloop()