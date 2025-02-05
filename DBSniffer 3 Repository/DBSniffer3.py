import os  # Import the os module for interacting with the operating system
import re  # Import the regular expression module for pattern matching
import pickle  # Import the pickle module for object serialization
import sqlite3  # Import the sqlite3 module for SQLite database operations
import smtplib  # Import the smtplib module for sending emails
import subprocess  # Import the subprocess module for running external commands
import configparser  # Import the configparser module for reading configuration files
from scapy.all import *  # Import the scapy library for packet manipulation
import platform as plform  # Import the platform module for retrieving system information
from email.mime.text import MIMEText  # Import MIMEText for creating email text
from email.mime.multipart import MIMEMultipart  # Import MIMEMultipart for creating email with attachments

class IntrusionDetectionSystem:
    def __init__(self):
        # Define regular expression patterns for SQL intrusion detection
        self.IDS_RULES = [
            r'SELECT\s.*?\bFROM\b.*?\bWHERE\b',
            r'DROP\s.*?\bTABLE\b',
            r'UPDATE\s.*?\bSET\b',
            r'INSERT\s.*?\bINTO\b',
            r'ALTER\s.*?\bTABLE\b'
        ]
        # Define actions corresponding to SQL intrusion detection patterns
        self.IPS_ACTIONS = {
            r'SELECT\s.*?\bFROM\b.*?\bWHERE\b': 'Block unauthorized SELECT queries',
            r'DROP\s.*?\bTABLE\b': 'Block DROP TABLE statements',
            r'UPDATE\s.*?\bSET\b': 'Block unauthorized UPDATE queries',
            r'INSERT\s.*?\bINTO\b': 'Block unauthorized INSERT queries',
            r'ALTER\s.*?\bTABLE\b': 'Block ALTER TABLE statements'
        }
        # Define paths for storing authorized commands and SQLite database
        self.database_path = 'mysql_commands.db'
        self.AUTHORIZED_COMMANDS_FILE = 'authorized_commands.pkl'
        # Load authorized commands from file or initialize an empty list
        self.AUTHORIZED_COMMANDS = self.load_authorized_commands()
        # Get the network interface based on the operating system
        self.INTERFACE = self.get_network_interface()
        # Read configuration settings from 'config.ini'
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')
        # Track processed network packets to avoid duplication
        self.seq_no = set()

    def get_network_interface(self):
        # Determine the network interface based on the operating system
        system = plform.system()
        if system == 'Windows':
            return 'Ethernet'  # Replace with appropriate interface name on Windows
        elif system == 'Linux':
            return 'lo'  # Replace with appropriate interface name on Linux
        elif system == 'Darwin':
            return 'en0'  # Replace with appropriate interface name on Darwin
        else:
            raise ValueError(f"Unsupported operating system: {system}")

    def load_authorized_commands(self):
        try:
            # Attempt to load authorized commands from the pickle file
            with open(self.AUTHORIZED_COMMANDS_FILE, 'rb') as file:
                return pickle.load(file)
        except FileNotFoundError:
            # Return an empty list if the file is not found
            return []

    def save_authorized_commands(self):
        # Save the authorized commands to the pickle file
        with open(self.AUTHORIZED_COMMANDS_FILE, 'wb') as file:
            pickle.dump(self.AUTHORIZED_COMMANDS, file)

    def store_commands_in_database(self, learned_command,table_name):
        try:
            # Create an SQLite database and table if it doesn't exist
            if not os.path.exists(self.database_path):
                conn = sqlite3.connect(self.database_path)
                c = conn.cursor()
                table_query = 'CREATE TABLE good_query (id INTEGER PRIMARY KEY AUTOINCREMENT, command TEXT)'
                c.execute(table_query)
                table_query = 'CREATE TABLE bad_query (id INTEGER PRIMARY KEY AUTOINCREMENT, command TEXT)' 
                c.execute(table_query)
                conn.commit()
                conn.close()

            # Insert the learned command into the SQLite database
            conn = sqlite3.connect(self.database_path)
            c = conn.cursor()
            query = "INSERT INTO %s (command) VALUES ('%s')" % (table_name,learned_command,)
            query = query.replace('\x00', '')  # Remove null bytes to prevent SQL injection
            c.execute(query)

            conn.commit()
            conn.close()

        except sqlite3.Error as e:
            print(f"SQLite error: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

    def send_email(self, subject,intrusion_type, intrusion_details):
        # Get email configuration settings from 'config.ini'
        sender_email = self.config.get('Email', 'sender_email')
        recipient_email = self.config.get('Email', 'recipient_email')
        smtp_server = self.config.get('Email', 'smtp_server')
        smtp_port = self.config.getint('Email', 'smtp_port')
        smtp_username = self.config.get('Email', 'smtp_username')
        smtp_password = self.config.get('Email', 'smtp_password')

        body = f"""
                ⚠️ Intrusion Detection Alert:

                Subject: {subject}
                Type: {intrusion_type}

                Details:
                {intrusion_details}
                """

        # Create an email message with the specified subject and body
        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = recipient_email
        message['Subject'] = subject
        message.attach(MIMEText(body, 'plain'))

        # Connect to the SMTP server, login, and send the email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(sender_email, recipient_email, message.as_string())
        server.quit()

    def block_intrusion(self, command, packet,ips_action):
        # Display intrusion detection information and take actions to block communication
        print(f"Intrusion detected: {command}")
        print("Generating alarm...")
        self.send_email('Intrusion Detected', f"Intrusion detected: {command}",ips_action)
        print("Preventing further communication...")
        attacker_ip = packet[IP].src
        system = plform.system()
        # Implement actions based on the operating system
        if system == 'Linux':
            subprocess.run(['iptables', '-A', 'INPUT', '-s', attacker_ip, '-j', 'DROP'], check=True)
            subprocess.run(['sudo', 'service', 'mysql', 'stop'])
        elif system == 'Windows':
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name="Block Attack"',
                            'dir=in', 'srcip=' + attacker_ip,
                            'action=block'], check=True)
            subprocess.run(["net", "stop", "MySQL"])
        elif system == 'Darwin':
            subprocess.run(['pfctl', '-t', 'blacklist', '-T', 'add', + attacker_ip])
            subprocess.run(['sudo', 'service', 'mysql', 'stop'])
        else:
            print("Unsupported operating system")

    def packet_handler(self, packet,pcap_file_path):
        if pcap_file_path:
            wrpcap(pcap_file_path, packet,append=True)
        # Handle packets and perform intrusion detection
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if b'caching_sha2_password' in packet[Raw].load or b'@@version_comment' in packet[Raw].load or b'server_host' in packet[Raw].load or packet[Raw].load[:2]==b'\x14\x00' :
                return
            
            if packet[TCP].seq in self.seq_no:
                return

            self.seq_no.add(packet[TCP].seq)

            authorized_query = False
            # Check if the payload matches any intrusion detection rules
            for rule in self.IDS_RULES:
                if re.search(rule, payload, re.IGNORECASE):
                    ips_action = self.IPS_ACTIONS.get(rule)
                    if ips_action:
                        table_name = "bad_query"
                        print(f"IPS action: {ips_action}")
                        self.store_commands_in_database(payload,table_name)
                        self.block_intrusion(payload, packet,ips_action)
                    else:
                        print("No action specified for the detected rule.")
                    break
            else:
                authorized_query = True

            # Process authorized queries and update the list of authorized commands
            if authorized_query:
                if payload not in self.AUTHORIZED_COMMANDS:
                    self.AUTHORIZED_COMMANDS.append(payload)
                    print(f"Learning: Added new authorized command: {payload}")
                    self.save_authorized_commands()
                    table_name = "good_query"
                    self.store_commands_in_database(payload,table_name)
                else:
                    print(f"Authorized query: {payload}")

    @staticmethod
    def pcap_file_func():
        pcapfile_path = input("Please choose path for pcap file: ")
        pcap_file_name = input("Please choose pcap file name: ")
        pcap_file_path = f'{pcapfile_path}/{pcap_file_name}.pcap'
        print(f"Your pcap file will be stored at {pcap_file_path}")
        return pcap_file_path

    def start_packet_sniffing(self):
        # Start packet sniffing using scapy library
        try:
            iface = input("Please specify your interface: ")  # Prompt user for network interface
            create_pcapfile = input("do you want to create a PCAP file? if yes please enter y else n: ")
            pcap_file_path =None
            if create_pcapfile.lower()=="y":
                pcap_file_path = self.pcap_file_func()
                cnf_path = input("do you want to change pcap file path? if yes please enter y else n: ")
                if cnf_path.lower()=="y" :
                    pcap_file_path = self.pcap_file_func()

            sniff(iface=iface, prn=lambda packet: self.packet_handler(packet, pcap_file_path), filter="tcp dst port 3306")

        except PermissionError:
            print("Insufficient permissions. Please run as root or administrator.")


if __name__ == "__main__":
    # Entry point when the script is executed
    intrusion_detection_system = IntrusionDetectionSystem()
    intrusion_detection_system.start_packet_sniffing()
