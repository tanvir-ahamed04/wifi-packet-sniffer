from scapy.all import get_if_list
from scapy.arch.windows import get_windows_if_list
from globals import *

def get_sniffable_interfaces():
    scapy_ifaces = get_if_list()
    windows_ifaces = get_windows_if_list()
    display_map = {}
    for iface in windows_ifaces:
        name = iface.get("name", "")
        desc = iface.get("description", "")
        guid = iface.get("guid", "")
        display_name = f"{name} - {desc}"
        for scapy_iface in scapy_ifaces:
            if name.lower() in scapy_iface.lower() or guid.lower() in scapy_iface.lower():
                display_map[display_name] = scapy_iface
                break
    return display_map