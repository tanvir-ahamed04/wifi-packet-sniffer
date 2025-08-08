from globals import *
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


def show_graph():
    graph_win = tk.Toplevel(root)
    graph_win.title("Packet Graphs")
    graph_win.geometry("800x500")
    tab_parent = ttk.Notebook(graph_win)

    # Tab 1: Packet Rate Over Time
    tab1 = tk.Frame(tab_parent)
    fig1, ax1 = plt.subplots(figsize=(8,4))
    canvas1 = FigureCanvasTkAgg(fig1, master=tab1)
    canvas1.get_tk_widget().pack(fill="both", expand=True)
    tab_parent.add(tab1, text="Packets/sec (60s)")

    # Tab 2: Protocol Distribution
    tab2 = tk.Frame(tab_parent)
    fig2, ax2 = plt.subplots(figsize=(8,4))
    canvas2 = FigureCanvasTkAgg(fig2, master=tab2)
    canvas2.get_tk_widget().pack(fill="both", expand=True)
    tab_parent.add(tab2, text="Protocol Distribution")

    tab_parent.pack(fill="both", expand=True)

    def update_graphs():
        # --- Packet rate graph ---
        window = 60  # seconds to show
        now = time_mod.time()
        recent = [t for t in packet_times if now - t < window]
        ax1.clear()
        if recent:
            bins = list(range(int(now-window), int(now)+1))
            ax1.hist(recent, bins=bins, color='blue')
            ax1.set_xlim([now-window, now])
        ax1.set_title("Packets per Second (last 60s)")
        ax1.set_xlabel("Unix Time (s)")
        ax1.set_ylabel("Count")
        fig1.tight_layout()
        canvas1.draw()

        # --- Protocol Pie chart ---
        ax2.clear()
        if protocol_counts:
            labels = list(protocol_counts.keys())
            sizes = list(protocol_counts.values())
            ax2.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
            ax2.axis('equal')
            ax2.set_title("Protocol Distribution")
        else:
            ax2.text(0.5, 0.5, "No data yet", ha='center', va='center', fontsize=14)
        fig2.tight_layout()
        canvas2.draw()

        graph_win.after(1000, update_graphs)
    update_graphs()
