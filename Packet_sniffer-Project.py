import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pyshark
import socket
from threading import Thread
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import csv
from collections import Counter

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")

        # Authentication
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.authenticated = False

        self.auth_frame = ttk.Frame(root)
        ttk.Label(self.auth_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        ttk.Entry(self.auth_frame, textvariable=self.username).grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(self.auth_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        ttk.Entry(self.auth_frame, textvariable=self.password, show="*").grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(self.auth_frame, text="Login", command=self.login).grid(row=2, column=0, columnspan=2, pady=10)
        self.auth_frame.pack(pady=50)

        # Upper Full Region
        self.upper_frame = ttk.Frame(root)
        self.upper_frame.pack(fill="both", expand=True)

        # Filter Entry and Button Frame
        self.filter_button_frame = ttk.Frame(self.upper_frame)
        self.filter_button_frame.pack(side=tk.TOP, fill="both", expand=True)

        self.filter_entry = tk.Entry(self.filter_button_frame)
        self.filter_entry.grid(row=0, column=0, padx=10, pady=10, sticky='w')
        self.filter_entry.insert(0, "Source IP Filter")

        # Main Treeview
        self.tree = ttk.Treeview(self.upper_frame, columns=("Source IP", "Source Domain", "Destination IP", "Destination Domain", "Protocol"))
        self.tree.heading("#0", text="Packet Number")
        self.tree.column("#0", width=100)
        self.tree.heading("Source IP", text="Source IP")
        self.tree.column("Source IP", width=150)
        self.tree.heading("Source Domain", text="Source Domain")
        self.tree.column("Source Domain", width=200)
        self.tree.heading("Destination IP", text="Destination IP")
        self.tree.column("Destination IP", width=150)
        self.tree.heading("Destination Domain", text="Destination Domain")
        self.tree.column("Destination Domain", width=200)
        self.tree.heading("Protocol", text="Protocol")
        self.tree.column("Protocol", width=100)
        self.tree.pack(side=tk.TOP, fill="both", expand=True)

        # Buttons
        self.button_frame = ttk.Frame(self.filter_button_frame)
        self.button_frame.grid(row=0, column=1, padx=10, pady=10)

        self.start_button = tk.Button(self.button_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, padx=10, pady=10)

        self.stop_button = tk.Button(self.button_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=10, pady=10)

        self.details_button = tk.Button(self.button_frame, text="Show Packet Details", command=self.show_details)
        self.details_button.grid(row=0, column=2, padx=10, pady=10)
        self.details_button["state"] = "disabled"

        self.graph_button = tk.Button(self.button_frame, text="Show Graph", command=self.show_graph)
        self.graph_button.grid(row=0, column=3, padx=10, pady=10)
        self.graph_button["state"] = "disabled"

        self.export_button = tk.Button(self.button_frame, text="Export to CSV", command=self.export_to_csv)
        self.export_button.grid(row=0, column=4, padx=10, pady=10)
        self.export_button["state"] = "disabled"

        # Packet Count Graph and Protocol Distribution Pie Chart Frames
        self.graph_frame = ttk.Frame(self.upper_frame)
        self.graph_frame.pack(side=tk.TOP, fill="both", expand=True)

        # Packet Count Graph
        self.packet_count_frame = ttk.Frame(self.graph_frame)
        self.packet_count_frame.pack(side=tk.LEFT, padx=10, pady=10, fill="both", expand=True)

        self.figure, self.ax = plt.subplots()
        self.ax.set_title('Live Packet Count')
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('Packet Count')
        self.ax.grid(True, linestyle='--', alpha=0.6)
        self.packet_count = 0
        self.x_data = []
        self.y_data = []
        self.line, = self.ax.plot(self.x_data, self.y_data, label='Packets', color='#1f78b4', linewidth=2, linestyle='-')
        self.ax.legend()
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.packet_count_frame)
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

        # Protocol Distribution Pie Chart
        self.protocol_pie_frame = ttk.Frame(self.graph_frame)
        self.protocol_pie_frame.pack(side=tk.RIGHT, padx=10, pady=10, fill="both", expand=True)

        self.protocol_pie_figure, self.protocol_pie_ax = plt.subplots()
        self.protocol_pie_ax.set_title('Protocol Distribution')
        self.protocol_pie_canvas = FigureCanvasTkAgg(self.protocol_pie_figure, master=self.protocol_pie_frame)
        self.protocol_pie_canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

        self.protocol_pie_chart = None

        self.packet_number = 1
        self.sniff_thread = None
        self.stop_sniffing_flag = False

        self.copyright_label = ttk.Label(self.upper_frame, text=" © Copyright Shubham Gupta(COEP CSE). All Rights Reserved", font=('Helvetica', 10, 'italic'))
        self.copyright_label.pack(side=tk.TOP, pady=10)

    def login(self):
        if self.username.get() == "sgubuntu" and self.password.get() == "sgubuntu":
            self.auth_frame.destroy()
            self.authenticated = True
            self.start_button["state"] = "normal"
            self.details_button["state"] = "normal"
            self.graph_button["state"] = "normal"
            self.export_button["state"] = "normal"
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def update_protocol_pie_chart(self):
        if not self.authenticated:
            return

        # Count protocol occurrences
        protocols = [self.tree.item(item, 'values')[4] for item in self.tree.get_children()]
        protocol_counts = Counter(protocols)

        # Update pie chart
        if self.protocol_pie_chart:
            self.protocol_pie_ax.clear()  # Clear the existing chart
            self.protocol_pie_ax.set_title('Protocol Distribution')
            self.protocol_pie_ax.pie(
                protocol_counts.values(), labels=protocol_counts.keys(), autopct='%1.1f%%', startangle=90
            )
            self.protocol_pie_ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
            self.protocol_pie_canvas.draw()
        else:
            self.protocol_pie_chart = self.protocol_pie_ax.pie(
                protocol_counts.values(), labels=protocol_counts.keys(), autopct='%1.1f%%', startangle=90
            )
            self.protocol_pie_ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
            self.protocol_pie_canvas.draw()

    def update_graph(self):
        self.x_data.append(self.packet_count)
        self.y_data.append(self.packet_number)

        self.line.set_xdata(self.x_data)
        self.line.set_ydata(self.y_data)

        self.ax.relim()
        self.ax.autoscale_view()

        self.canvas.draw()

    def start_sniffing(self):
        if not self.authenticated:
            messagebox.showerror("Authentication Error", "Please login first.")
            return

        self.start_button["state"] = "disabled"
        self.stop_button["state"] = "normal"
        self.export_button["state"] = "normal"
        self.sniff_thread = Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.start_button["state"] = "normal"
        self.stop_button["state"] = "disabled"
        self.export_button["state"] = "normal"
        self.stop_sniffing_flag = True

    def show_details(self):
        if not self.authenticated:
            messagebox.showerror("Authentication Error", "Please login first.")
            return

        selected_item = self.tree.selection()
        if selected_item:
            packet_number = self.tree.item(selected_item, "text")
            packet_details = f"Packet Number: {packet_number}\n"
            packet_details += f"Source IP: {self.tree.item(selected_item, 'values')[0]}\n"
            packet_details += f"Source Domain: {self.tree.item(selected_item, 'values')[1]}\n"
            packet_details += f"Destination IP: {self.tree.item(selected_item, 'values')[2]}\n"
            packet_details += f"Destination Domain: {self.tree.item(selected_item, 'values')[3]}\n"
            packet_details += f"Protocol: {self.tree.item(selected_item, 'values')[4]}"

            messagebox.showinfo("Packet Details", packet_details)
        else:
            messagebox.showwarning("No Selection", "Please select a packet to view details.")

    def show_graph(self):
        if not self.authenticated:
            messagebox.showerror("Authentication Error", "Please login first.")
            return

        plt.figure()
        plt.plot(self.x_data, self.y_data, label='Packets', color='#1f78b4', linewidth=2, linestyle='-')
        plt.title('Packet Count Graph')
        plt.xlabel('Time')
        plt.ylabel('Packet Count')
        plt.legend()
        plt.grid(True, linestyle='--', alpha=0.6)
        plt.show()

    def resolve_domain(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return ip

    def sniff_packets(self):
        capture = pyshark.LiveCapture(interface="wlp0s20f3")
        for packet in capture.sniff_continuously():
            if self.stop_sniffing_flag:
                break

            try:
                src_ip = packet.ip.src
                dest_ip = packet.ip.dst
                proto = packet.transport_layer

                src_domain = self.resolve_domain(src_ip)
                dest_domain = self.resolve_domain(dest_ip)

                filter_criteria = self.filter_entry.get().strip()

                if filter_criteria and src_ip != filter_criteria:
                    continue  # Skip packets that do not match the filter criteria

                # Alternating row colors
                bg_color = "#FFFFFF" if self.packet_number % 2 == 0 else "#F0F0F0"

                self.tree.insert("", "end", text=str(self.packet_number),
                                 values=(src_ip, src_domain, dest_ip, dest_domain, proto),
                                 tags=("oddrow" if self.packet_number % 2 == 1 else "evenrow"))

                self.packet_number += 1
                self.packet_count += 1
                self.update_graph()
                self.update_protocol_pie_chart()  # Update the protocol pie chart after each packet

            except (AttributeError, socket.herror, socket.gaierror):
                pass  # Skip packets that do not have necessary information

    def export_to_csv(self):
        if not self.authenticated:
            messagebox.showerror("Authentication Error", "Please login first.")
            return

        # Ask the user for the file path to save the CSV file
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])

        if not file_path:
            return  # User canceled the file dialog

        with open(file_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Packet Number", "Source IP", "Source Domain", "Destination IP", "Destination Domain", "Protocol"])

            for item in self.tree.get_children():
                values = self.tree.item(item, 'values')
                writer.writerow([self.tree.item(item, 'text')] + list(values))

        messagebox.showinfo("Export Successful", f"Packet details exported to {file_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
