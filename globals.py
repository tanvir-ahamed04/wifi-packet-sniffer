# globals.py
import threading
import queue
from scapy.all import sniff, Ether, IP, TCP, UDP, get_if_list
from scapy.layers.l2 import Ether
from scapy.arch.windows import get_windows_if_list
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv
import time as time_mod



# Packet capturing related
packet_queue = queue.Queue()
stop_sniffing = threading.Event()
packet_details = []
all_rows = []
packet_times = []
protocol_counts = {}

# GUI globals (initialized later in gui.py)
root = None
tree = None
start_btn = None
stop_btn = None
interface_var = None
filter_var = None
iface_map = None
cols = ('Time', 'Src MAC', 'Src IP', 'Dst MAC', 'Dst IP', 'Protocol', 'Length', 'Info')
