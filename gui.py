from globals import *
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time as time_mod
import csv
from sniffing import start_sniffing, get_sniffable_interfaces
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from graphing import *
from exports import *

def update_table():
    while not packet_queue.empty():
        row, details = packet_queue.get()
        all_rows.append(row)
        packet_details.append(details)
        tree.insert('', 'end', values=row)
    root.after(100, update_table)

def clear_table():
    for item in tree.get_children():
        tree.delete(item)

def on_start():
    global interface_var, iface_map, filter_var, start_btn, stop_btn
    selected_display = interface_var.get()
    selected_iface = iface_map.get(selected_display)
    filter_text = filter_var.get().strip()
    if not selected_iface:
        messagebox.showwarning("No Interface", "Please select a valid network interface.")
        return
    start_btn.config(state="disabled")
    stop_btn.config(state="normal")
    stop_sniffing.clear()
    packet_details.clear()
    all_rows.clear()
    packet_times.clear()
    protocol_counts.clear()
    clear_table()
    threading.Thread(target=start_sniffing, args=(selected_iface, filter_text), daemon=True).start()

def on_stop():
    global start_btn, stop_btn
    stop_sniffing.set()
    start_btn.config(state="normal")
    stop_btn.config(state="disabled")

def on_exit():
    stop_sniffing.set()
    root.destroy()

def on_row_double_click(event):
    selected = tree.focus()
    if not selected:
        return
    try:
        idx = tree.index(selected)
        details = packet_details[idx]
    except Exception:
        details = "No details available."
    detail_win = tk.Toplevel(root)
    detail_win.title("Packet Details")
    detail_win.geometry("700x600")
    txt = tk.Text(detail_win, wrap=tk.WORD)
    txt.insert(tk.END, details)
    txt.config(state=tk.DISABLED)
    txt.pack(fill="both", expand=True, padx=10, pady=10)
    scrollbar = ttk.Scrollbar(detail_win, orient='vertical', command=txt.yview)
    txt.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side='right', fill='y')

def setup_gui():
    global root, tree, start_btn, stop_btn, interface_var, filter_var, iface_map
    
    root = tk.Tk()
    root.title('Wi-Fi Packet Sniffer (Tanvir-Ahamed)')
    root.geometry('1100x650')

    frame = tk.Frame(root)
    frame.pack(pady=6, padx=40, fill='x')

    tk.Label(frame, text="Select Interface:").pack(side="left", padx=5)

    iface_map = get_sniffable_interfaces()
    interface_var = tk.StringVar()
    interface_dropdown = ttk.Combobox(frame, textvariable=interface_var,
                                     values=list(iface_map.keys()), state="readonly")
    if iface_map:
        interface_dropdown.set(list(iface_map.keys())[0])
    interface_dropdown.pack(side="left", padx=5)

    tk.Label(frame, text="Filter:").pack(side="left", padx=5)
    filter_var = tk.StringVar()
    filter_entry = tk.Entry(frame, textvariable=filter_var, width=20)
    filter_entry.pack(side="left", padx=5)

    start_btn = tk.Button(frame, text="Start Capture", command=on_start)
    start_btn.pack(side="left", padx=5)
    stop_btn = tk.Button(frame, text="Stop Capture", command=on_stop, state="disabled")
    stop_btn.pack(side="left", padx=5)
    exit_btn = tk.Button(frame, text="Exit", command=on_exit)
    exit_btn.pack(side="left", padx=5)


    # Export/Graph Frame
    export_graph_frame = tk.Frame(root)
    export_graph_frame.pack(pady=3, padx=40, fill='x')

    export_txt_btn = tk.Button(export_graph_frame, text="Export TXT", command=export_txt)
    export_txt_btn.pack(side="right", padx=5)
    export_csv_btn = tk.Button(export_graph_frame, text="Export CSV", command=export_csv)
    export_csv_btn.pack(side="right", padx=5)

    graph_btn = tk.Button(export_graph_frame, text="Graph View", command=show_graph)
    graph_btn.pack(side="right", padx=5)

    # Packet Table with scrollbars
    table_frame = tk.Frame(root)
    table_frame.pack(fill='both', expand=True, padx=40, pady=10)

    cols = ('Time', 'Src MAC', 'Src IP', 'Dst MAC', 'Dst IP', 'Protocol', 'Length', 'Info')
    tree = ttk.Treeview(table_frame, columns=cols, show='headings')
    for col in cols:
        tree.heading(col, text=col)
        width = 320 if col == 'Info' else 130 if col not in ('Protocol', 'Length') else 80
        tree.column(col, width=width)
    tree.pack(side='left', fill='both', expand=True)

    scrollbar_y = ttk.Scrollbar(table_frame, orient='vertical', command=tree.yview)
    tree.configure(yscroll=scrollbar_y.set)
    scrollbar_y.pack(side='right', fill='y')

    scrollbar_x = ttk.Scrollbar(root, orient='horizontal', command=tree.xview)
    tree.configure(xscroll=scrollbar_x.set)
    scrollbar_x.pack(side='bottom', fill='x')

    tree.bind("<Double-1>", on_row_double_click)

    update_table()
    root.protocol("WM_DELETE_WINDOW", on_exit)
    root.mainloop()
