from scapy.all import sniff, Ether, IP, TCP, UDP, wrpcap
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox

# GUI Application
class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("800x600")

        # Create a text area to display packets
        self.packet_display = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=25)
        self.packet_display.pack(padx=10, pady=10)

        # Button frame
        button_frame = tk.Frame(root)
        button_frame.pack(pady=5)

        # Start button
        self.start_button = tk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)

        # Stop button
        self.stop_button = tk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Save button
        self.save_button = tk.Button(button_frame, text="Save Packets", command=self.save_packets, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=5)

        # Sniffing control flag
        self.is_sniffing = False
        self.captured_packets = []

    # Function to process each packet
    def process_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

            packet_info = f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}\n"

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                packet_info += f"TCP -> Source Port: {src_port}, Destination Port: {dst_port}\n"

            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                packet_info += f"UDP -> Source Port: {src_port}, Destination Port: {dst_port}\n"

            packet_info += "-" * 50 + "\n"

            # Display packet info in the GUI
            self.packet_display.insert(tk.END, packet_info)
            self.packet_display.yview(tk.END)

            # Save packet for later
            self.captured_packets.append(packet)

    # Start sniffing
    def start_sniffing(self):
        self.is_sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)
        self.packet_display.delete(1.0, tk.END)  # Clear previous packets
        self.captured_packets = []  # Reset captured packets
        print("Sniffing started...")

        # Start sniffing in a separate thread
        import threading
        sniff_thread = threading.Thread(target=self.sniff_packets)
        sniff_thread.start()

    # Stop sniffing
    def stop_sniffing(self):
        self.is_sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.NORMAL)
        print("Sniffing stopped.")

    # Sniff packets
    def sniff_packets(self):
        sniff(prn=self.process_packet, stop_filter=lambda x: not self.is_sniffing)

    # Save captured packets to a file
    def save_packets(self):
        if not self.captured_packets:
            messagebox.showwarning("No Packets", "No packets captured to save.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if file_path:
            wrpcap(file_path, self.captured_packets)
            messagebox.showinfo("Saved", f"Packets saved to {file_path}")

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()