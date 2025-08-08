import csv
from globals import *

def export_txt():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt")])
    if not file_path:
        return
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            for idx, row in enumerate(all_rows):
                f.write(" | ".join(str(col) for col in row) + "\n")
                f.write(packet_details[idx] + "\n")
                f.write("-" * 40 + "\n")
        messagebox.showinfo("Export", f"Exported to {file_path}")
    except Exception as e:
        messagebox.showerror("Export Error", str(e))

def export_csv():
    file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV files", "*.csv")])
    if not file_path:
        return
    try:
        with open(file_path, "w", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(cols + ("Details",))
            for idx, row in enumerate(all_rows):
                writer.writerow(row + (packet_details[idx],))
        messagebox.showinfo("Export", f"Exported to {file_path}")
    except Exception as e:
        messagebox.showerror("Export Error", str(e))
