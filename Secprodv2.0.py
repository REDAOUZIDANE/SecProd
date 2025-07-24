import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import random
import threading
import time
from datetime import datetime, timedelta
import queue
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN
from PIL import Image, ImageTk
import json
import csv
import socket
import struct
import hashlib
import ipaddress
from collections import deque
import webbrowser
import platform
import psutil
import uuid
import fpdf
from fpdf import FPDF
from mpl_toolkits.mplot3d import Axes3D
import openai  # pip install openai

# ======================
# INDUSTRIAL PROTOCOLS
# ======================
class IndustrialProtocol:
    MODBUS_TCP = "Modbus/TCP"
    OPC_UA = "OPC UA"
    PROFINET = "PROFINET"
    DNP3 = "DNP3"
    IEC61850 = "IEC 61850"
    ETHERNET_IP = "EtherNet/IP"
    BACNET = "BACnet"
    IEC104 = "IEC 60870-5-104"
    S7COMM = "S7Comm (Siemens)"
    CIP = "Common Industrial Protocol"
    FINS = "FINS (Omron)"
    MELSEC = "MELSEC (Mitsubishi)"
    
    @classmethod
    def all_protocols(cls):
        return [p for p in cls.__dict__.values() if isinstance(p, str) and not p.startswith('__')]

# ======================
# INDUSTRIAL ATTACKS
# ======================
class IndustrialAttack:
    def __init__(self, name, protocol, severity, indicators, mitigation, cve=None):
        self.name = name
        self.protocol = protocol
        self.severity = severity  # Low, Medium, High, Critical
        self.indicators = indicators
        self.mitigation = mitigation
        self.last_detected = None
        self.detection_count = 0
        self.cve = cve if cve else f"CVE-{random.randint(2020, 2023)}-{random.randint(1000, 9999)}"
        self.tactics = random.choice(["Initial Access", "Execution", "Persistence", "Lateral Movement"])

# Known industrial cyber attacks with detailed indicators
INDUSTRIAL_ATTACKS = [
    IndustrialAttack(
        "Modbus Enumeration", 
        IndustrialProtocol.MODBUS_TCP, 
        "High",
        ["Function Code 43 (Read Device ID)", 
         "Multiple failed unit ID attempts (3+/min)",
         "Unusual polling intervals",
         "Scanning across register ranges"],
        ["Implement access control lists", 
         "Enable Modbus/TCP security extensions",
         "Deploy protocol-aware firewall",
         "Monitor for enumeration patterns"],
        cve="CVE-2022-31814"
    ),
    IndustrialAttack(
        "Command Injection", 
        IndustrialProtocol.MODBUS_TCP, 
        "Critical",
        ["Unauthorized function code 6 (Write Single Register)", 
         "Out-of-range register writes",
         "Write commands to read-only areas",
         "Malformed packet structures"],
        ["Implement write protection", 
         "Deploy anomaly detection",
         "Segment control network",
         "Enable command signing"],
        cve="CVE-2021-44228"
    ),
    IndustrialAttack(
        "OPC UA Server Spoofing", 
        IndustrialProtocol.OPC_UA, 
        "High",
        ["Certificate mismatch", 
         "Unauthorized endpoint connection",
         "Invalid security policies",
         "Man-in-the-middle patterns"],
        ["Implement certificate pinning", 
         "Enforce endpoint validation",
         "Monitor for rogue servers",
         "Enable strict authentication"],
        cve="CVE-2023-1234"
    ),
    IndustrialAttack(
        "PROFINET Discovery", 
        IndustrialProtocol.PROFINET, 
        "Medium",
        ["Excessive DCP Identify requests (>5/sec)", 
         "Unauthorized LLDP traffic",
         "MAC address scanning",
         "Network topology probing"],
        ["Enable port security", 
         "Disable unused protocols",
         "Monitor for reconnaissance",
         "Implement network segmentation"],
        cve="CVE-2022-4567"
    ),
    IndustrialAttack(
        "DNP3 DoS", 
        IndustrialProtocol.DNP3, 
        "Critical",
        ["Malformed application layer fragments", 
         "Flood of confirm requests",
         "Invalid CRC values",
         "Session exhaustion attempts"],
        ["Implement DNP3 secure authentication", 
         "Rate limit confirm requests",
         "Validate message integrity",
         "Deploy protocol-aware IPS"],
        cve="CVE-2021-7890"
    ),
    IndustrialAttack(
        "IEC 61850 Goose Spoofing", 
        IndustrialProtocol.IEC61850, 
        "High",
        ["Unauthorized GOOSE packets", 
         "Abnormal multicast patterns",
         "Invalid timestamps",
         "Incorrect state numbers"],
        ["Implement GOOSE message signing", 
         "Monitor multicast traffic",
         "Validate packet timing",
         "Enable goose authentication"],
        cve="CVE-2023-3456"
    ),
    IndustrialAttack(
        "CIP Class 3 Scanning", 
        IndustrialProtocol.ETHERNET_IP, 
        "Medium",
        ["Excessive Class 3 service requests", 
         "Unregistered session initiation",
         "Invalid encapsulation commands",
         "Service code enumeration"],
        ["Restrict CIP services", 
         "Monitor session establishment",
         "Implement access controls",
         "Deploy deep packet inspection"],
        cve="CVE-2022-6789"
    ),
    IndustrialAttack(
        "S7Comm Stop CPU", 
        IndustrialProtocol.S7COMM, 
        "Critical",
        ["Function code 0x29 (Stop CPU)", 
         "Unauthorized PLC commands",
         "Invalid job references",
         "Malformed parameter blocks"],
        ["Implement command authorization", 
         "Monitor critical functions",
         "Segment PLC access",
         "Enable PLC write protection"],
        cve="CVE-2021-3712"
    ),
    IndustrialAttack(
        "BACnet Device Spoofing", 
        IndustrialProtocol.BACNET, 
        "High",
        ["Duplicate device IDs", 
         "Invalid BVLC messages",
         "Unauthorized Who-Is requests",
         "Broadcast storm patterns"],
        ["Implement BACnet security", 
         "Monitor device registration",
         "Validate BVLC headers",
         "Enable BACnet authentication"],
        cve="CVE-2023-2345"
    )
]

# ======================
# INDUSTRIAL ASSETS
# ======================
class IndustrialAsset:
    def __init__(self, asset_id, asset_type, ip_address, protocol, criticality):
        self.asset_id = asset_id
        self.asset_type = asset_type
        self.ip_address = ip_address
        self.protocol = protocol
        self.criticality = criticality  # Low, Medium, High, Critical
        self.status = "Normal"
        self.last_seen = datetime.now()
        self.vulnerabilities = []
        self.security_controls = []
        self.mac_address = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        self.firmware_version = f"{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 20)}"
        self.operating_hours = random.randint(100, 10000)
        self.location = random.choice(["Production Line A", "Control Room", "Substation 1", "Field Unit 3"])
    
    def add_vulnerability(self, cve_id, description, severity):
        self.vulnerabilities.append({
            'cve_id': cve_id,
            'description': description,
            'severity': severity,
            'detected': datetime.now(),
            'status': 'Unpatched',
            'cvss_score': round(random.uniform(3.0, 9.9), 1)
        })
    
    def add_security_control(self, control_type, status):
        self.security_controls.append({
            'type': control_type,
            'status': status,
            'last_checked': datetime.now(),
            'effectiveness': random.choice(["High", "Medium", "Low"])
        })

# ======================
# NETWORK TRAFFIC SIMULATION
# ======================
class IndustrialTrafficGenerator:
    def __init__(self):
        self.protocol_distribution = {
            IndustrialProtocol.MODBUS_TCP: 0.35,
            IndustrialProtocol.OPC_UA: 0.15,
            IndustrialProtocol.PROFINET: 0.12,
            IndustrialProtocol.DNP3: 0.08,
            IndustrialProtocol.ETHERNET_IP: 0.10,
            IndustrialProtocol.S7COMM: 0.10,
            IndustrialProtocol.BACNET: 0.05,
            IndustrialProtocol.IEC61850: 0.05
        }
        self.normal_traffic_ranges = {
            IndustrialProtocol.MODBUS_TCP: (5, 25),
            IndustrialProtocol.OPC_UA: (10, 40),
            IndustrialProtocol.PROFINET: (8, 30),
            IndustrialProtocol.DNP3: (3, 15),
            IndustrialProtocol.ETHERNET_IP: (5, 20),
            IndustrialProtocol.S7COMM: (4, 18),
            IndustrialProtocol.BACNET: (2, 10),
            IndustrialProtocol.IEC61850: (1, 8)
        }
        self.attack_traffic_multiplier = {
            "Low": 3,
            "Medium": 5,
            "High": 8,
            "Critical": 15
        }
        self.attack_duration = {
            "Low": (1, 3),
            "Medium": (2, 5),
            "High": (3, 8),
            "Critical": (5, 15)
        }
    
    def generate_normal_traffic(self, protocol):
        low, high = self.normal_traffic_ranges.get(protocol, (1, 10))
        return random.randint(low, high)
    
    def generate_attack_traffic(self, protocol, severity):
        base = self.generate_normal_traffic(protocol)
        return base * self.attack_traffic_multiplier.get(severity, 1)
    
    def get_attack_duration(self, severity):
        low, high = self.attack_duration.get(severity, (1, 5))
        return random.randint(low, high)

# ======================
# PDF REPORT GENERATION
# ======================
class PDFReport(FPDF):
    def __init__(self):
        super().__init__()
        self.WIDTH = 210
        self.HEIGHT = 297
    
    def header(self):
        # Custom header with logo and title
        try:
            self.image('scureprod_logo.png', 10, 8, 25)
        except Exception as e:
            print(f"Logo image not found: {e}")
        self.set_font('Arial', 'B', 15)
        self.cell(self.WIDTH - 20)
        self.cell(10, 10, 'Industrial Security Report', 0, 0, 'R')
        self.ln(20)
    
    def footer(self):
        # Page footer
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, 'Page ' + str(self.page_no()), 0, 0, 'C')
    
    def chapter_title(self, title):
        # Chapter title
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 6, title, 0, 1, 'L', 1)
        self.ln(4)
    
    def chapter_body(self, body):
        # Chapter text
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 5, body)
        self.ln()
    
    def add_table(self, headers, data):
        # Add a table to the report
        self.set_font('Arial', 'B', 10)
        col_count = len(headers)
        col_widths = [self.WIDTH // col_count for _ in range(col_count)]
        
        # Headers
        for i, header in enumerate(headers):
            self.cell(col_widths[i], 7, header, 1, 0, 'C')
        self.ln()
        
        # Data
        self.set_font('Arial', '', 9)
        for row in data:
            for i, item in enumerate(row):
                self.cell(col_widths[i], 6, str(item), 1)
            self.ln()

# ======================
# MAIN APPLICATION
# ======================
class ScureProdApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ScureProd | Industrial Cyber Defense Platform")
        self.root.geometry("1600x1000")
        self.root.state('zoomed')  # Start maximized
        
        # System information
        self.system_id = str(uuid.uuid4())[:8]
        self.operator = "Industrial Security Operator"
        self.facility = "ACME Manufacturing Plant"
        
        # Custom Dark Theme (modernized)
        self.bg_color = "#181a20"
        self.card_color = "#232634"
        self.text_color = "#f5f6fa"
        self.accent_color = "#4a90e2"
        self.alert_color = "#e74c3c"
        self.safe_color = "#27ae60"
        self.warning_color = "#f1c40f"
        self.critical_color = "#c0392b"
        self.info_color = "#3498db"
        self.border_color = "#353b48"
        self.selected_row_color = "#2d3a4a"
        self.alt_row_color = "#20232a"
        self.font_family = "Segoe UI"
        # Setup styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('.', background=self.bg_color, foreground=self.text_color, font=(self.font_family, 10))
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.text_color, font=(self.font_family, 10))
        self.style.configure('Header.TLabel', font=(self.font_family, 18, 'bold'), foreground=self.accent_color, background=self.bg_color)
        self.style.configure('Card.TFrame', background=self.card_color, relief=tk.RAISED, borderwidth=2)
        self.style.configure('TButton', background=self.accent_color, foreground="white", borderwidth=0, font=(self.font_family, 10, 'bold'), padding=6)
        self.style.map('TButton', background=[('active', '#357ab8')])
        self.style.configure('Red.TButton', background=self.alert_color, foreground="white")
        self.style.map('Red.TButton', background=[('active', '#a93226')])
        self.style.configure('Green.TButton', background=self.safe_color, foreground="white")
        self.style.map('Green.TButton', background=[('active', '#229954')])
        self.style.configure('TNotebook', background=self.bg_color)
        self.style.configure('TNotebook.Tab', background=self.card_color, foreground=self.text_color, font=(self.font_family, 11, 'bold'), padding=[10, 5])
        self.style.map('TNotebook.Tab', background=[('selected', self.accent_color)])
        # Treeview styling
        self.style.configure('Treeview', background=self.card_color, foreground=self.text_color, fieldbackground=self.card_color, font=(self.font_family, 10), rowheight=28, borderwidth=0)
        self.style.configure('Treeview.Heading', background=self.accent_color, foreground='white', font=(self.font_family, 11, 'bold'))
        self.style.map('Treeview', background=[('selected', self.selected_row_color)])
        
        # Initialize components
        self.traffic_generator = IndustrialTrafficGenerator()
        self.assets = []
        self.alerts = []
        self.attack_log = []
        self.network_traffic = []
        self.protocol_traffic = {p: deque(maxlen=100) for p in IndustrialProtocol.all_protocols()}
        self.alert_queue = queue.Queue()
        self.threat_level = 0
        self.attack_patterns = INDUSTRIAL_ATTACKS
        self.ai_models = {}
        self.models_trained = False
        self.last_incident_report = None
        self.attack_in_progress = False
        self.current_attack = None
        
        # Create UI components
        self.create_menu()
        self.create_header()
        self.create_main_panels()
        
        # Initialize with sample data
        self.initialize_sample_assets()
        self.initialize_ai_models()
        
        # Start background services
        self.running = True
        threading.Thread(target=self.simulate_industrial_network, daemon=True).start()
        threading.Thread(target=self.process_alerts, daemon=True).start()
        threading.Thread(target=self.train_ai_models, daemon=True).start()
        threading.Thread(target=self.monitor_asset_health, daemon=True).start()
        threading.Thread(target=self.detect_anomalies, daemon=True).start()
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def create_menu(self):
        """Create the application menu bar"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Save Session", command=self.save_session)
        file_menu.add_command(label="Load Session", command=self.load_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Asset Discovery", command=self.run_asset_discovery)
        tools_menu.add_command(label="Vulnerability Scan", command=self.run_vulnerability_scan)
        tools_menu.add_command(label="Configuration Backup", command=self.backup_configurations)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Reports menu
        report_menu = tk.Menu(menubar, tearoff=0)
        report_menu.add_command(label="Generate Security Report", command=self.generate_report)
        report_menu.add_command(label="View Threat Intelligence", command=self.show_threat_intel)
        menubar.add_cascade(label="Reports", menu=report_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_header(self):
        """Create the application header with system info"""
        header_frame = ttk.Frame(self.root, style='Card.TFrame')
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Logo and title
        logo_label = ttk.Label(header_frame, text="⚡ ScureProd", font=('Arial', 18, 'bold'), style='Header.TLabel')
        logo_label.pack(side=tk.LEFT, padx=10)
        
        # System info
        info_frame = ttk.Frame(header_frame)
        info_frame.pack(side=tk.RIGHT, padx=10)
        
        ttk.Label(info_frame, text=f"Facility: {self.facility}", font=('Arial', 10)).pack(anchor=tk.E)
        ttk.Label(info_frame, text=f"Operator: {self.operator}", font=('Arial', 10)).pack(anchor=tk.E)
        ttk.Label(info_frame, text=f"System ID: {self.system_id}", font=('Arial', 10)).pack(anchor=tk.E)
        
        # Threat level indicator
        self.threat_frame = ttk.Frame(header_frame, style='Card.TFrame')
        self.threat_frame.pack(side=tk.RIGHT, padx=20)
        
        ttk.Label(self.threat_frame, text="Threat Level:", font=('Arial', 10)).pack(side=tk.LEFT)
        self.threat_label = ttk.Label(self.threat_frame, text="0%", font=('Arial', 10, 'bold'))
        self.threat_label.pack(side=tk.LEFT, padx=5)
        
        # Time display
        self.time_label = ttk.Label(header_frame, text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), font=('Arial', 10))
        self.time_label.pack(side=tk.RIGHT, padx=10)
        self.update_time()
    
    def create_main_panels(self):
        """Create the main application panels using a notebook"""
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        # Dashboard tab
        dashboard_tab = ttk.Frame(notebook)
        self.create_dashboard(dashboard_tab)
        notebook.add(dashboard_tab, text="Dashboard")
        # Assets tab
        assets_tab = ttk.Frame(notebook)
        self.create_asset_panel(assets_tab)
        notebook.add(assets_tab, text="Assets")
        # Network tab
        network_tab = ttk.Frame(notebook)
        self.create_network_monitor(network_tab)
        notebook.add(network_tab, text="Network")
        # Alerts tab
        alerts_tab = ttk.Frame(notebook)
        self.create_alert_panel(alerts_tab)
        notebook.add(alerts_tab, text="Alerts")
        # Response tab
        response_tab = ttk.Frame(notebook)
        self.create_incident_response_panel(response_tab)
        notebook.add(response_tab, text="Incident Response")
        # Heatmap 3D tab
        heatmap_tab = ttk.Frame(notebook)
        self.create_heatmap3d_panel(heatmap_tab)
        notebook.add(heatmap_tab, text="Heatmap 3D")
        # AI Chatbot tab
        chatbot_tab = ttk.Frame(notebook)
        self.create_chatbot_panel(chatbot_tab)
        notebook.add(chatbot_tab, text="AI Chatbot")
        # Metrics tab
        metrics_tab = ttk.Frame(notebook)
        self.create_metrics_panel(metrics_tab)
        notebook.add(metrics_tab, text="Industry Metrics")
    
    def create_dashboard(self, parent):
        """Create the main dashboard with overview widgets"""
        # Top row - summary cards
        top_frame = ttk.Frame(parent)
        top_frame.pack(fill=tk.X, pady=5)
        
        # Asset summary card
        asset_card = ttk.Frame(top_frame, style='Card.TFrame', padding=10)
        asset_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(asset_card, text="Assets", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        self.asset_summary_label = ttk.Label(asset_card, text="0 Total | 0 Critical", font=('Arial', 10))
        self.asset_summary_label.pack(anchor=tk.W)
        
        # Alert summary card
        alert_card = ttk.Frame(top_frame, style='Card.TFrame', padding=10)
        alert_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(alert_card, text="Alerts", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        self.alert_summary_label = ttk.Label(alert_card, text="0 Total | 0 Unacknowledged", font=('Arial', 10))
        self.alert_summary_label.pack(anchor=tk.W)
        
        # Protocol summary card
        protocol_card = ttk.Frame(top_frame, style='Card.TFrame', padding=10)
        protocol_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(protocol_card, text="Protocols", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        self.protocol_summary_label = ttk.Label(protocol_card, text="0 Active | 0 Anomalous", font=('Arial', 10))
        self.protocol_summary_label.pack(anchor=tk.W)
        
        # Security summary card
        security_card = ttk.Frame(top_frame, style='Card.TFrame', padding=10)
        security_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(security_card, text="Security", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        self.security_summary_label = ttk.Label(security_card, text="0 Vulnerabilities", font=('Arial', 10))
        self.security_summary_label.pack(anchor=tk.W)
        
        # Middle row - network graph
        middle_frame = ttk.Frame(parent)
        middle_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        graph_card = ttk.Frame(middle_frame, style='Card.TFrame')
        graph_card.pack(fill=tk.BOTH, expand=True, padx=5)
        
        self.figure = plt.Figure(figsize=(8, 4), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.figure, graph_card)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add toolbar
        toolbar = NavigationToolbar2Tk(self.canvas, graph_card)
        toolbar.update()
        self.canvas._tkcanvas.pack(fill=tk.BOTH, expand=True)
        
        # Bottom row - recent alerts and quick actions
        bottom_frame = ttk.Frame(parent)
        bottom_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Recent alerts
        alert_frame = ttk.Frame(bottom_frame, style='Card.TFrame', padding=10)
        alert_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(alert_frame, text="Recent Alerts", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        
        self.recent_alerts_tree = ttk.Treeview(alert_frame, columns=('time', 'alert', 'severity'), show='headings', height=5)
        self.recent_alerts_tree.heading('time', text='Time')
        self.recent_alerts_tree.heading('alert', text='Alert')
        self.recent_alerts_tree.heading('severity', text='Severity')
        self.recent_alerts_tree.column('time', width=120)
        self.recent_alerts_tree.column('alert', width=250)
        self.recent_alerts_tree.column('severity', width=80)
        self.recent_alerts_tree.pack(fill=tk.BOTH, expand=True)
        
        # Quick actions
        action_frame = ttk.Frame(bottom_frame, style='Card.TFrame', padding=10)
        action_frame.pack(side=tk.LEFT, fill=tk.BOTH, padx=5)
        ttk.Label(action_frame, text="Quick Actions", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        
        ttk.Button(action_frame, text="Acknowledge All Alerts", command=self.acknowledge_all_alerts).pack(fill=tk.X, pady=2)
        ttk.Button(action_frame, text="Isolate Critical Assets", command=self.isolate_critical_assets).pack(fill=tk.X, pady=2)
        ttk.Button(action_frame, text="Generate Security Report", command=self.generate_report).pack(fill=tk.X, pady=2)
        ttk.Button(action_frame, text="Run Asset Discovery", command=self.run_asset_discovery).pack(fill=tk.X, pady=2)
        ttk.Button(action_frame, text="Emergency Shutdown", command=self.emergency_shutdown, style='Red.TButton').pack(fill=tk.X, pady=10)
    
    def create_asset_panel(self, parent):
        """Create the asset management panel"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Asset list
        list_frame = ttk.Frame(main_frame, style='Card.TFrame')
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Search and filter
        search_frame = ttk.Frame(list_frame)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.asset_search = ttk.Entry(search_frame)
        self.asset_search.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.asset_search.bind('<KeyRelease>', self.filter_assets)
        
        ttk.Button(search_frame, text="Refresh", command=self.refresh_assets).pack(side=tk.LEFT)
        
        # Asset treeview
        self.asset_tree = ttk.Treeview(list_frame, columns=('id', 'type', 'ip', 'protocol', 'status'), show='headings')
        self.asset_tree.heading('id', text='ID')
        self.asset_tree.heading('type', text='Type')
        self.asset_tree.heading('ip', text='IP Address')
        self.asset_tree.heading('protocol', text='Protocol')
        self.asset_tree.heading('status', text='Status')
        
        self.asset_tree.column('id', width=100)
        self.asset_tree.column('type', width=150)
        self.asset_tree.column('ip', width=120)
        self.asset_tree.column('protocol', width=120)
        self.asset_tree.column('status', width=100)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.asset_tree.yview)
        self.asset_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.asset_tree.pack(fill=tk.BOTH, expand=True)
        
        # Asset details
        detail_frame = ttk.Frame(main_frame, style='Card.TFrame', width=400)
        detail_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(5, 0))
        
        self.asset_detail_text = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, width=40, 
                                                         bg=self.card_color, fg=self.text_color,
                                                         font=('Consolas', 9))
        self.asset_detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bind selection event
        self.asset_tree.bind('<<TreeviewSelect>>', self.show_asset_details)
        
        # Populate assets
        self.refresh_assets()
    
    def create_network_monitor(self, parent):
        """Create the network monitoring panel"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Protocol traffic graph
        graph_frame = ttk.Frame(main_frame, style='Card.TFrame')
        graph_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        self.protocol_figure = plt.Figure(figsize=(8, 4), dpi=100)
        self.protocol_ax = self.protocol_figure.add_subplot(111)
        self.protocol_canvas = FigureCanvasTkAgg(self.protocol_figure, graph_frame)
        self.protocol_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Protocol details
        detail_frame = ttk.Frame(main_frame, style='Card.TFrame')
        detail_frame.pack(fill=tk.BOTH, expand=True)
        
        self.protocol_tree = ttk.Treeview(detail_frame, columns=('protocol', 'traffic', 'alerts', 'status'), show='headings')
        self.protocol_tree.heading('protocol', text='Protocol')
        self.protocol_tree.heading('traffic', text='Traffic (pkts/min)')
        self.protocol_tree.heading('alerts', text='Alerts')
        self.protocol_tree.heading('status', text='Status')
        
        self.protocol_tree.column('protocol', width=150)
        self.protocol_tree.column('traffic', width=100)
        self.protocol_tree.column('alerts', width=80)
        self.protocol_tree.column('status', width=100)
        
        scrollbar = ttk.Scrollbar(detail_frame, orient=tk.VERTICAL, command=self.protocol_tree.yview)
        self.protocol_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.protocol_tree.pack(fill=tk.BOTH, expand=True)
        
        # Populate protocols
        self.update_protocol_monitor()
    
    def create_alert_panel(self, parent):
        """Create the alert management panel"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Alert list
        list_frame = ttk.Frame(main_frame, style='Card.TFrame')
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Filter controls
        filter_frame = ttk.Frame(list_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
        self.alert_filter = ttk.Combobox(filter_frame, values=["All", "Unacknowledged", "Critical", "High", "Medium", "Low"])
        self.alert_filter.current(0)
        self.alert_filter.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.alert_filter.bind('<<ComboboxSelected>>', self.filter_alerts)
        
        ttk.Button(filter_frame, text="Acknowledge", command=self.acknowledge_alert).pack(side=tk.LEFT, padx=5)
        
        # Alert treeview
        self.alert_tree = ttk.Treeview(list_frame, columns=('time', 'alert', 'severity', 'ack'), show='headings')
        self.alert_tree.heading('time', text='Time')
        self.alert_tree.heading('alert', text='Alert')
        self.alert_tree.heading('severity', text='Severity')
        self.alert_tree.heading('ack', text='Acknowledged')
        
        self.alert_tree.column('time', width=120)
        self.alert_tree.column('alert', width=250)
        self.alert_tree.column('severity', width=80)
        self.alert_tree.column('ack', width=100)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.alert_tree.yview)
        self.alert_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.alert_tree.pack(fill=tk.BOTH, expand=True)
        
        # Alert details
        detail_frame = ttk.Frame(main_frame, style='Card.TFrame', width=400)
        detail_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(5, 0))
        
        self.alert_detail_text = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, width=40, 
                                                         bg=self.card_color, fg=self.text_color,
                                                         font=('Consolas', 9))
        self.alert_detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Action buttons
        action_frame = ttk.Frame(detail_frame)
        action_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(action_frame, text="Mitigate", command=self.mitigate_alert).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        ttk.Button(action_frame, text="Isolate", command=self.isolate_alert_source, style='Red.TButton').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        # Bind selection event
        self.alert_tree.bind('<<TreeviewSelect>>', self.show_alert_details)
        
        # Populate alerts
        self.refresh_alerts()
    def create_incident_response_panel(self, parent):
        """Create the incident response panel"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Incident details
        detail_frame = ttk.Frame(main_frame, style='Card.TFrame')
        detail_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        ttk.Label(detail_frame, text="Active Incident", font=('Arial', 12, 'bold')).pack(anchor=tk.W, padx=5, pady=5)
        
        self.incident_text = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, height=8, 
                                                     bg=self.card_color, fg=self.text_color,
                                                     font=('Consolas', 9))
        self.incident_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))
        self.incident_text.insert(tk.END, "No active incidents detected")
        
        # Response actions
        action_frame = ttk.Frame(main_frame, style='Card.TFrame')
        action_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(action_frame, text="Response Actions", font=('Arial', 12, 'bold')).pack(anchor=tk.W, padx=5, pady=5)
        
        button_frame = ttk.Frame(action_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Button(button_frame, text="Contain Threat", command=self.contain_threat).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        ttk.Button(button_frame, text="Collect Evidence", command=self.collect_evidence).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        ttk.Button(button_frame, text="Eradicate", command=self.eradicate_threat).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        ttk.Button(button_frame, text="Recover", command=self.recover_systems).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        # Playbook frame
        playbook_frame = ttk.Frame(main_frame, style='Card.TFrame')
        playbook_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(playbook_frame, text="Response Playbook", font=('Arial', 12, 'bold')).pack(anchor=tk.W, padx=5, pady=5)
        
        self.playbook_tree = ttk.Treeview(playbook_frame, columns=('step', 'action', 'status'), show='headings')
        self.playbook_tree.heading('step', text='Step')
        self.playbook_tree.heading('action', text='Action')
        self.playbook_tree.heading('status', text='Status')
        
        self.playbook_tree.column('step', width=50)
        self.playbook_tree.column('action', width=300)
        self.playbook_tree.column('status', width=100)
        
        scrollbar = ttk.Scrollbar(playbook_frame, orient=tk.VERTICAL, command=self.playbook_tree.yview)
        self.playbook_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.playbook_tree.pack(fill=tk.BOTH, expand=True)
        
        # Populate with generic playbook
        self.load_incident_playbook()
    
    def initialize_sample_assets(self):
        """Initialize the application with sample industrial assets"""
        asset_types = [
            "PLC", "RTU", "HMI", "SCADA Server", "Engineering Workstation",
            "Historian", "IED", "Protection Relay", "VFD", "DCS Controller",
            "Safety Instrumented System", "Firewall", "Switch", "Router"
        ]
        
        protocols = IndustrialProtocol.all_protocols()
        
        for i in range(1, 25):
            asset_type = random.choice(asset_types)
            protocol = random.choice(protocols)
            criticality = random.choice(["Low", "Medium", "High", "Critical"])
            
            # Generate IP in industrial range
            ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            
            asset = IndustrialAsset(
                asset_id=f"ASSET-{i:03d}",
                asset_type=asset_type,
                ip_address=ip,
                protocol=protocol,
                criticality=criticality
            )
            
            # Add some vulnerabilities
            if random.random() < 0.4:  # 40% chance of having vulnerabilities
                num_vulns = random.randint(1, 3)
                for _ in range(num_vulns):
                    attack = random.choice(self.attack_patterns)
                    if attack.protocol == protocol:
                        asset.add_vulnerability(
                            attack.cve,
                            f"Vulnerable to {attack.name}",
                            attack.severity
                        )
            
            # Add some security controls
            if random.random() < 0.7:  # 70% chance of having security controls
                control_types = [
                    "Firewall Rules", "Access Control", "Patch Management",
                    "Network Segmentation", "Log Monitoring", "Backup",
                    "Authentication", "Encryption", "IDS/IPS"
                ]
                num_controls = random.randint(1, 4)
                for _ in range(num_controls):
                    asset.add_security_control(
                        random.choice(control_types),
                        random.choice(["Enabled", "Disabled", "Partial"])
                    )
            
            self.assets.append(asset)
        
        # Add some critical assets with specific configurations
        critical_assets = [
            ("PLC-001", "PLC", "192.168.1.10", IndustrialProtocol.MODBUS_TCP, "Critical"),
            ("SCADA-01", "SCADA Server", "192.168.1.100", IndustrialProtocol.OPC_UA, "Critical"),
            ("RTU-01", "RTU", "192.168.2.50", IndustrialProtocol.DNP3, "High"),
            ("HMI-01", "HMI", "192.168.1.20", IndustrialProtocol.ETHERNET_IP, "High")
        ]
        
        for asset_id, asset_type, ip, protocol, criticality in critical_assets:
            asset = IndustrialAsset(asset_id, asset_type, ip, protocol, criticality)
            
            # Add vulnerabilities to critical assets
            for attack in self.attack_patterns:
                if attack.protocol == protocol and random.random() < 0.6:
                    asset.add_vulnerability(
                        attack.cve,
                        f"Vulnerable to {attack.name}",
                        attack.severity
                    )
            
            # Add security controls
            asset.add_security_control("Firewall Rules", "Enabled")
            asset.add_security_control("Access Control", "Enabled")
            asset.add_security_control("Patch Management", "Partial")
            
            self.assets.append(asset)
        
        self.refresh_assets()
    
    def initialize_ai_models(self):
        """Initialize the AI/ML models for anomaly detection"""
        self.ai_models = {
            "Isolation Forest": IsolationForest(contamination=0.05),
            "One-Class SVM": OneClassSVM(nu=0.05),
            "DBSCAN": DBSCAN(eps=0.5, min_samples=5)
        }
        
        # Initialize with empty data
        for model in self.ai_models.values():
            X = np.random.rand(10, 1)  # Dummy data
            model.fit(X)
        
        self.models_trained = False
    
    def update_time(self):
        """Update the time display"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=now)
        self.root.after(1000, self.update_time)
    
    def refresh_assets(self):
        """Refresh the asset treeview"""
        for item in self.asset_tree.get_children():
            self.asset_tree.delete(item)
        
        for asset in sorted(self.assets, key=lambda x: x.asset_id):
            status_color = ""
            if asset.status == "Normal":
                status_color = self.safe_color
            elif asset.status == "Warning":
                status_color = self.warning_color
            elif asset.status == "Critical":
                status_color = self.critical_color
            
            self.asset_tree.insert('', tk.END, values=(
                asset.asset_id,
                asset.asset_type,
                asset.ip_address,
                asset.protocol,
                asset.status
            ), tags=(status_color,))
        
        # Configure tag colors
        self.asset_tree.tag_configure(self.safe_color, foreground=self.safe_color)
        self.asset_tree.tag_configure(self.warning_color, foreground=self.warning_color)
        self.asset_tree.tag_configure(self.critical_color, foreground=self.critical_color)
        
        # Update summary
        total_assets = len(self.assets)
        critical_assets = len([a for a in self.assets if a.criticality == "Critical"])
        self.asset_summary_label.config(text=f"{total_assets} Total | {critical_assets} Critical")
    
    def filter_assets(self, event=None):
        """Filter assets based on search criteria (now actually hides non-matching rows)"""
        query = self.asset_search.get().lower()
        # Remove all items
        for item in self.asset_tree.get_children():
            self.asset_tree.delete(item)
        # Re-add only matching assets
        for asset in sorted(self.assets, key=lambda x: x.asset_id):
            values = (
                asset.asset_id,
                asset.asset_type,
                asset.ip_address,
                asset.protocol,
                asset.status
            )
            if query in " ".join(str(v).lower() for v in values):
                status_color = ""
                if asset.status == "Normal":
                    status_color = self.safe_color
                elif asset.status == "Warning":
                    status_color = self.warning_color
                elif asset.status == "Critical":
                    status_color = self.critical_color
                self.asset_tree.insert('', tk.END, values=values, tags=(status_color,))
        # Configure tag colors
        self.asset_tree.tag_configure(self.safe_color, foreground=self.safe_color)
        self.asset_tree.tag_configure(self.warning_color, foreground=self.warning_color)
        self.asset_tree.tag_configure(self.critical_color, foreground=self.critical_color)
    
    def show_asset_details(self, event):
        """Show detailed information about the selected asset"""
        selected = self.asset_tree.selection()
        if not selected:
            return
        
        item = selected[0]
        asset_id = self.asset_tree.item(item, 'values')[0]
        asset = next((a for a in self.assets if a.asset_id == asset_id), None)
        
        if not asset:
            return
        
        details = f"Asset ID: {asset.asset_id}\n"
        details += f"Type: {asset.asset_type}\n"
        details += f"IP Address: {asset.ip_address}\n"
        details += f"MAC Address: {asset.mac_address}\n"
        details += f"Protocol: {asset.protocol}\n"
        details += f"Criticality: {asset.criticality}\n"
        details += f"Status: {asset.status}\n"
        details += f"Location: {asset.location}\n"
        details += f"Firmware: {asset.firmware_version}\n"
        details += f"Operating Hours: {asset.operating_hours}\n"
        details += f"Last Seen: {asset.last_seen.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        details += "=== Vulnerabilities ===\n"
        if asset.vulnerabilities:
            for vuln in asset.vulnerabilities:
                details += f"- {vuln['cve_id']} ({vuln['severity']}, CVSS: {vuln['cvss_score']})\n"
                details += f"  {vuln['description']}\n"
                details += f"  Status: {vuln['status']}, Detected: {vuln['detected'].strftime('%Y-%m-%d')}\n"
        else:
            details += "No known vulnerabilities\n"
        
        details += "\n=== Security Controls ===\n"
        if asset.security_controls:
            for control in asset.security_controls:
                details += f"- {control['type']}: {control['status']} (Effectiveness: {control['effectiveness']})\n"
                details += f"  Last checked: {control['last_checked'].strftime('%Y-%m-%d %H:%M')}\n"
        else:
            details += "No security controls configured\n"
        
        self.asset_detail_text.config(state=tk.NORMAL)
        self.asset_detail_text.delete(1.0, tk.END)
        self.asset_detail_text.insert(tk.END, details)
        self.asset_detail_text.config(state=tk.DISABLED)
    
    def refresh_alerts(self):
        """Refresh the alert treeview"""
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)
        
        for alert in sorted(self.alerts, key=lambda x: x['time'], reverse=True)[:100]:  # Show most recent 100
            severity = alert['severity']
            color = self.text_color
            if severity == "Critical":
                color = self.critical_color
            elif severity == "High":
                color = self.alert_color
            elif severity == "Medium":
                color = self.warning_color
            elif severity == "Low":
                color = self.info_color
            
            self.alert_tree.insert('', tk.END, values=(
                alert['time'].strftime("%Y-%m-%d %H:%M:%S"),
                alert['message'],
                severity,
                "Yes" if alert['acknowledged'] else "No"
            ), tags=(color,))
        
        # Configure tag colors
        self.alert_tree.tag_configure(self.critical_color, foreground=self.critical_color)
        self.alert_tree.tag_configure(self.alert_color, foreground=self.alert_color)
        self.alert_tree.tag_configure(self.warning_color, foreground=self.warning_color)
        self.alert_tree.tag_configure(self.info_color, foreground=self.info_color)
        
        # Update summary
        total_alerts = len(self.alerts)
        unacknowledged = len([a for a in self.alerts if not a['acknowledged']])
        self.alert_summary_label.config(text=f"{total_alerts} Total | {unacknowledged} Unacknowledged")
    
    def filter_alerts(self, event=None):
        """Filter alerts based on selected criteria (now actually hides non-matching rows)"""
        filter_value = self.alert_filter.get()
        # Remove all items
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)
        # Re-add only matching alerts
        for alert in sorted(self.alerts, key=lambda x: x['time'], reverse=True)[:100]:
            severity = alert['severity']
            color = self.text_color
            if severity == "Critical":
                color = self.critical_color
            elif severity == "High":
                color = self.alert_color
            elif severity == "Medium":
                color = self.warning_color
            elif severity == "Low":
                color = self.info_color
            show = False
            if filter_value == "All":
                show = True
            elif filter_value == "Unacknowledged" and not alert['acknowledged']:
                show = True
            elif filter_value == severity:
                show = True
            if show:
                self.alert_tree.insert('', tk.END, values=(
                    alert['time'].strftime("%Y-%m-%d %H:%M:%S"),
                    alert['message'],
                    severity,
                    "Yes" if alert['acknowledged'] else "No"
                ), tags=(color,))
        # Configure tag colors
        self.alert_tree.tag_configure(self.critical_color, foreground=self.critical_color)
        self.alert_tree.tag_configure(self.alert_color, foreground=self.alert_color)
        self.alert_tree.tag_configure(self.warning_color, foreground=self.warning_color)
        self.alert_tree.tag_configure(self.info_color, foreground=self.info_color)
    
    def show_alert_details(self, event):
        """Show detailed information about the selected alert"""
        selected = self.alert_tree.selection()
        if not selected:
            return
        
        item = selected[0]
        alert_time = datetime.strptime(self.alert_tree.item(item, 'values')[0], "%Y-%m-%d %H:%M:%S")
        alert = next((a for a in self.alerts if a['time'] == alert_time), None)
        
        if not alert:
            return
        
        details = f"Time: {alert['time'].strftime('%Y-%m-%d %H:%M:%S')}\n"
        details += f"Severity: {alert['severity']}\n"
        details += f"Source: {alert.get('source', 'Unknown')}\n"
        details += f"Protocol: {alert.get('protocol', 'N/A')}\n"
        details += f"Acknowledged: {'Yes' if alert['acknowledged'] else 'No'}\n\n"
        details += f"Message: {alert['message']}\n\n"
        
        if 'indicators' in alert:
            details += "=== Indicators ===\n"
            for indicator in alert['indicators']:
                details += f"- {indicator}\n"
        
        if 'mitigation' in alert:
            details += "\n=== Recommended Actions ===\n"
            for action in alert['mitigation']:
                details += f"- {action}\n"
        
        if 'cve' in alert:
            details += f"\nAssociated CVE: {alert['cve']}\n"
        
        self.alert_detail_text.config(state=tk.NORMAL)
        self.alert_detail_text.delete(1.0, tk.END)
        self.alert_detail_text.insert(tk.END, details)
        self.alert_detail_text.config(state=tk.DISABLED)
    
    def acknowledge_alert(self):
        """Acknowledge the selected alert"""
        selected = self.alert_tree.selection()
        if not selected:
            return
        
        item = selected[0]
        alert_time = datetime.strptime(self.alert_tree.item(item, 'values')[0], "%Y-%m-%d %H:%M:%S")
        
        for alert in self.alerts:
            if alert['time'] == alert_time:
                alert['acknowledged'] = True
                break
        
        self.refresh_alerts()
    
    def acknowledge_all_alerts(self):
        """Acknowledge all alerts"""
        for alert in self.alerts:
            alert['acknowledged'] = True
        
        self.refresh_alerts()
        messagebox.showinfo("Success", "All alerts have been acknowledged")
    
    def mitigate_alert(self):
        """Initiate mitigation for the selected alert"""
        selected = self.alert_tree.selection()
        if not selected:
            return
        
        item = selected[0]
        alert_time = datetime.strptime(self.alert_tree.item(item, 'values')[0], "%Y-%m-%d %H:%M:%S")
        alert = next((a for a in self.alerts if a['time'] == alert_time), None)
        
        if not alert:
            return
        
        # Create a mitigation playbook
        self.playbook_tree.delete(*self.playbook_tree.get_children())
        
        steps = [
            (1, f"Isolate affected asset: {alert.get('source', 'Unknown')}", "Pending"),
            (2, f"Block malicious IP: {alert.get('attacker_ip', 'Unknown')}", "Pending"),
            (3, "Apply recommended security controls", "Pending"),
            (4, "Verify system integrity", "Pending"),
            (5, "Restore normal operations", "Pending")
        ]
        
        for step, action, status in steps:
            self.playbook_tree.insert('', tk.END, values=(step, action, status))
        
        # Update the incident panel
        self.incident_text.config(state=tk.NORMAL)
        self.incident_text.delete(1.0, tk.END)
        self.incident_text.insert(tk.END, f"Active Incident: {alert['message']}\n\n")
        self.incident_text.insert(tk.END, f"Severity: {alert['severity']}\n")
        self.incident_text.insert(tk.END, f"Time Detected: {alert['time'].strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.incident_text.insert(tk.END, f"Source: {alert.get('source', 'Unknown')}\n")
        self.incident_text.config(state=tk.DISABLED)
        
        messagebox.showinfo("Mitigation Started", "Incident response playbook has been initialized")
    
    def isolate_alert_source(self):
        """Isolate the source of the selected alert"""
        selected = self.alert_tree.selection()
        if not selected:
            return
        
        item = selected[0]
        alert_time = datetime.strptime(self.alert_tree.item(item, 'values')[0], "%Y-%m-%d %H:%M:%S")
        alert = next((a for a in self.alerts if a['time'] == alert_time), None)
        
        if not alert:
            return
        
        source = alert.get('source', None)
        if source:
            # Find the asset
            asset = next((a for a in self.assets if a.asset_id == source or a.ip_address == source), None)
            if asset:
                asset.status = "Isolated"
                self.refresh_assets()
                
                # Add an alert
                self.add_alert(
                    f"Asset {asset.asset_id} has been isolated",
                    "Isolation",
                    "High",
                    source=asset.asset_id,
                    mitigation=["Review isolation status", "Investigate root cause"]
                )
                
                messagebox.showinfo("Success", f"Asset {asset.asset_id} has been isolated")
            else:
                messagebox.showerror("Error", "Could not find asset to isolate")
        else:
            messagebox.showerror("Error", "No source information available for this alert")
    
    def isolate_critical_assets(self):
        """Isolate all critical assets as a precaution"""
        critical_assets = [a for a in self.assets if a.criticality == "Critical"]
        
        if not critical_assets:
            messagebox.showinfo("Info", "No critical assets found")
            return
        
        if messagebox.askyesno("Confirm", f"Isolate {len(critical_assets)} critical assets?"):
            for asset in critical_assets:
                asset.status = "Isolated"
            
            self.refresh_assets()
            
            self.add_alert(
                f"{len(critical_assets)} critical assets have been isolated",
                "Isolation",
                "High",
                mitigation=["Review isolation status", "Investigate threats"]
            )
            
            messagebox.showinfo("Success", f"{len(critical_assets)} critical assets isolated")
    
    def emergency_shutdown(self):
        """Initiate emergency shutdown procedure"""
        if messagebox.askyesno("EMERGENCY SHUTDOWN", 
                             "WARNING: This will initiate emergency shutdown procedures!\n\n"
                             "Are you sure you want to continue?", icon='warning'):
            
            # Isolate all critical assets
            for asset in self.assets:
                if asset.criticality in ["High", "Critical"]:
                    asset.status = "Isolated"
            
            # Create a high priority alert
            self.add_alert(
                "EMERGENCY SHUTDOWN INITIATED",
                "System",
                "Critical",
                mitigation=["Investigate emergency", "Review system logs"]
            )
            
            # Update UI
            self.refresh_assets()
            self.threat_level = 100
            self.update_threat_level()
            
            messagebox.showwarning("Shutdown Initiated", 
                                 "Emergency shutdown procedures activated!\n\n"
                                 "All critical assets have been isolated.")
    
    def load_incident_playbook(self):
        """Load the default incident response playbook"""
        self.playbook_tree.delete(*self.playbook_tree.get_children())
        
        steps = [
            (1, "Identify affected systems", "Pending"),
            (2, "Contain the incident", "Pending"),
            (3, "Collect forensic evidence", "Pending"),
            (4, "Eradicate the threat", "Pending"),
            (5, "Recover systems", "Pending"),
            (6, "Post-incident review", "Pending")
        ]
        
        for step, action, status in steps:
            self.playbook_tree.insert('', tk.END, values=(step, action, status))
    
    def contain_threat(self):
        """Execute containment procedures"""
        for item in self.playbook_tree.get_children():
            values = self.playbook_tree.item(item, 'values')
            if "Contain" in values[1]:
                self.playbook_tree.item(item, values=(values[0], values[1], "In Progress"))
                break
        
        # Simulate containment
        threading.Thread(target=self.simulate_containment).start()
    
    def simulate_containment(self):
        """Simulate containment procedures"""
        time.sleep(2)
        
        for item in self.playbook_tree.get_children():
            values = self.playbook_tree.item(item, 'values')
            if "Contain" in values[1]:
                self.playbook_tree.item(item, values=(values[0], values[1], "Completed"))
                break
        
        self.add_alert(
            "Threat containment procedures completed",
            "Incident Response",
            "Medium",
            mitigation=["Verify containment", "Proceed with eradication"]
        )
    
    def collect_evidence(self):
        """Execute evidence collection procedures"""
        for item in self.playbook_tree.get_children():
            values = self.playbook_tree.item(item, 'values')
            if "Collect" in values[1]:
                self.playbook_tree.item(item, values=(values[0], values[1], "In Progress"))
                break
        
        # Simulate evidence collection
        threading.Thread(target=self.simulate_evidence_collection).start()
    
    def simulate_evidence_collection(self):
        """Simulate evidence collection"""
        time.sleep(3)
        
        for item in self.playbook_tree.get_children():
            values = self.playbook_tree.item(item, 'values')
            if "Collect" in values[1]:
                self.playbook_tree.item(item, values=(values[0], values[1], "Completed"))
                break
        
        self.add_alert(
            "Forensic evidence collection completed",
            "Incident Response",
            "Medium",
            mitigation=["Analyze collected evidence", "Update threat intelligence"]
        )
    
    def eradicate_threat(self):
        """Execute threat eradication procedures"""
        for item in self.playbook_tree.get_children():
            values = self.playbook_tree.item(item, 'values')
            if "Eradicate" in values[1]:
                self.playbook_tree.item(item, values=(values[0], values[1], "In Progress"))
                break
        
        # Simulate eradication
        threading.Thread(target=self.simulate_eradication).start()
    
    def simulate_eradication(self):
        """Simulate threat eradication"""
        time.sleep(4)
        
        for item in self.playbook_tree.get_children():
            values = self.playbook_tree.item(item, 'values')
            if "Eradicate" in values[1]:
                self.playbook_tree.item(item, values=(values[0], values[1], "Completed"))
                break
        
        self.add_alert(
            "Threat eradication procedures completed",
            "Incident Response",
            "Medium",
            mitigation=["Verify eradication", "Prepare for recovery"]
        )
    
    def recover_systems(self):
        """Execute system recovery procedures"""
        for item in self.playbook_tree.get_children():
            values = self.playbook_tree.item(item, 'values')
            if "Recover" in values[1]:
                self.playbook_tree.item(item, values=(values[0], values[1], "In Progress"))
                break
        
        # Simulate recovery
        threading.Thread(target=self.simulate_recovery).start()
    
    def simulate_recovery(self):
        """Simulate system recovery"""
        time.sleep(5)
        
        # Restore isolated assets
        for asset in self.assets:
            if asset.status == "Isolated":
                asset.status = "Normal"
        
        self.refresh_assets()
        
        for item in self.playbook_tree.get_children():
            values = self.playbook_tree.item(item, 'values')
            if "Recover" in values[1]:
                self.playbook_tree.item(item, values=(values[0], values[1], "Completed"))
                break
        
        self.add_alert(
            "System recovery procedures completed",
            "Incident Response",
            "Medium",
            mitigation=["Monitor system stability", "Conduct post-incident review"]
        )
        
        # Reset threat level
        self.threat_level = 0
        self.update_threat_level()
        
        # Clear incident
        self.incident_text.config(state=tk.NORMAL)
        self.incident_text.delete(1.0, tk.END)
        self.incident_text.insert(tk.END, "No active incidents detected")
        self.incident_text.config(state=tk.DISABLED)
    
    def update_protocol_monitor(self):
        """Update the protocol traffic monitoring display"""
        self.protocol_tree.delete(*self.protocol_tree.get_children())
        
        for protocol, traffic in self.protocol_traffic.items():
            if not traffic:
                continue
            
            # Calculate average traffic
            last10 = list(traffic)[-10:]
            avg_traffic = sum(last10) / len(last10)
            
            # Count alerts for this protocol
            alert_count = len([a for a in self.alerts if a.get('protocol') == protocol])
            
            # Determine status
            if alert_count > 5:
                status = "Critical"
                status_color = self.critical_color
            elif alert_count > 2:
                status = "Warning"
                status_color = self.warning_color
            else:
                status = "Normal"
                status_color = self.safe_color
            
            self.protocol_tree.insert('', tk.END, values=(
                protocol,
                f"{avg_traffic:.1f}",
                alert_count,
                status
            ), tags=(status_color,))
        
        # Configure tag colors
        self.protocol_tree.tag_configure(self.safe_color, foreground=self.safe_color)
        self.protocol_tree.tag_configure(self.warning_color, foreground=self.warning_color)
        self.protocol_tree.tag_configure(self.critical_color, foreground=self.critical_color)
        
        # Update protocol summary
        active_protocols = len([p for p, t in self.protocol_traffic.items() if t])
        anomalous_protocols = len([p for p, t in self.protocol_traffic.items() 
                                 if t and max(list(t)[-10:]) > 2 * (sum(list(t)[-10:])/len(list(t)[-10:]))])
        self.protocol_summary_label.config(text=f"{active_protocols} Active | {anomalous_protocols} Anomalous")
    
    def update_network_graph(self):
        """Update the network traffic graph"""
        self.ax.clear()
        
        # Prepare data
        protocols = []
        traffic = []
        colors = []
        
        for protocol, values in self.protocol_traffic.items():
            if values:
                protocols.append(protocol)
                last10 = list(values)[-10:]
                traffic.append(sum(last10) / len(last10))  # Average of last 10
                
                # Color based on alerts
                alert_count = len([a for a in self.alerts if a.get('protocol') == protocol])
                if alert_count > 5:
                    colors.append(self.critical_color)
                elif alert_count > 2:
                    colors.append(self.warning_color)
                else:
                    colors.append(self.accent_color)
        
        if not protocols:
            return
        
        # Create bar chart
        x = range(len(protocols))
        bars = self.ax.bar(x, traffic, color=colors)
        
        # Add labels
        self.ax.set_xticks(x)
        self.ax.set_xticklabels(protocols, rotation=45, ha='right')
        self.ax.set_ylabel('Traffic (pkts/min)')
        self.ax.set_title('Industrial Protocol Traffic')
        
        # Add value labels
        for bar in bars:
            height = bar.get_height()
            self.ax.text(bar.get_x() + bar.get_width()/2., height,
                        f'{height:.1f}',
                        ha='center', va='bottom')
        
        self.figure.tight_layout()
        self.canvas.draw()
    
    def update_protocol_graph(self):
        """Update the protocol-specific traffic graph"""
        self.protocol_ax.clear()
        
        # Show traffic for all protocols
        for protocol, traffic in self.protocol_traffic.items():
            if traffic:
                self.protocol_ax.plot(traffic, label=protocol)
        
        self.protocol_ax.set_xlabel('Time (minutes)')
        self.protocol_ax.set_ylabel('Traffic (pkts/min)')
        self.protocol_ax.set_title('Protocol Traffic Over Time')
        self.protocol_ax.legend()
        self.protocol_ax.grid(True)
        
        self.protocol_figure.tight_layout()
        self.protocol_canvas.draw()
    
    def update_threat_level(self):
        """Update the threat level indicator"""
        self.threat_label.config(text=f"{self.threat_level}%")
        
        # Change color based on level
        if self.threat_level >= 75:
            self.threat_label.config(foreground=self.critical_color)
        elif self.threat_level >= 50:
            self.threat_label.config(foreground=self.warning_color)
        elif self.threat_level >= 25:
            self.threat_label.config(foreground=self.info_color)
        else:
            self.threat_label.config(foreground=self.safe_color)
    
    def add_alert(self, message, source, severity, x=None, y=None, **kwargs):
        """Add a new alert to the system"""
        alert = {
            'time': datetime.now(),
            'message': message,
            'source': source,
            'severity': severity,
            'acknowledged': False
        }
        
        # Add additional fields
        for key, value in kwargs.items():
            alert[key] = value
        
        self.alerts.append(alert)
        
        # Add to queue for processing
        self.alert_queue.put(alert)
        
        # Update UI
        self.refresh_alerts()
        
        # Show notification for high severity alerts
        if severity in ["Critical", "High"]:
            self.show_notification(message, severity)
        
        # If alert has a location, update the heatmap data
        if x is not None and y is not None:
            self.heatmap_data[y, x] += self.severity_to_intensity(severity)
    
    def severity_to_intensity(self, severity):
        # Map severity to a heatmap increment value
        return {
            "Critical": 30,
            "High": 20,
            "Medium": 10,
            "Low": 5
        }.get(severity, 1)
    
    def show_notification(self, message, severity):
        """Show a notification popup for important alerts (thread-safe)"""
        def notify():
            if severity == "Critical":
                title = "CRITICAL ALERT"
                icon = "warning"
            elif severity == "High":
                title = "HIGH PRIORITY ALERT"
                icon = "warning"
            else:
                title = "ALERT NOTIFICATION"
                icon = "info"
            messagebox.showwarning(title, message)
        self.root.after(0, notify)
    
    def process_alerts(self):
        """Background process to handle alert processing"""
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=0.5)
                
                # Update threat level based on alert severity
                if alert['severity'] == "Critical":
                    self.threat_level = min(100, self.threat_level + 15)
                elif alert['severity'] == "High":
                    self.threat_level = min(100, self.threat_level + 10)
                elif alert['severity'] == "Medium":
                    self.threat_level = min(100, self.threat_level + 5)
                else:
                    self.threat_level = min(100, self.threat_level + 2)
                
                self.update_threat_level()
                
                # Update recent alerts
                self.update_recent_alerts()
                
            except queue.Empty:
                pass
            
            # Gradually reduce threat level when no alerts
            if random.random() < 0.1 and self.threat_level > 0:
                self.threat_level = max(0, self.threat_level - 1)
                self.update_threat_level()
    
    def update_recent_alerts(self):
        """Update the recent alerts display on dashboard"""
        self.recent_alerts_tree.delete(*self.recent_alerts_tree.get_children())
        
        for alert in sorted(self.alerts, key=lambda x: x['time'], reverse=True)[:5]:
            self.recent_alerts_tree.insert('', tk.END, values=(
                alert['time'].strftime("%H:%M:%S"),
                alert['message'][:40] + "..." if len(alert['message']) > 40 else alert['message'],
                alert['severity']
            ))
    
    def simulate_industrial_network(self):
        """Simulate industrial network traffic and attacks"""
        while self.running:
            try:
                # Generate normal traffic
                for protocol in self.protocol_traffic.keys():
                    traffic = self.traffic_generator.generate_normal_traffic(protocol)
                    self.protocol_traffic[protocol].append(traffic)
                
                # Randomly trigger attacks
                if not self.attack_in_progress and random.random() < 0.05:  # 5% chance of attack
                    self.trigger_attack()
                
                # Update displays
                self.update_network_graph()
                self.update_protocol_graph()
                self.update_protocol_monitor()
                
                # Update asset statuses
                self.update_asset_statuses()
                
                time.sleep(1)
                
            except Exception as e:
                print(f"Error in network simulation: {e}")
                time.sleep(1)
    
    def trigger_attack(self):
        """Trigger a simulated industrial attack"""
        self.attack_in_progress = True
        attack = random.choice(self.attack_patterns)
        self.current_attack = attack
        
        # Select target asset
        target_assets = [a for a in self.assets if a.protocol == attack.protocol]
        if not target_assets:
            self.attack_in_progress = False
            return
        
        target = random.choice(target_assets)
        
        # Calculate duration
        duration = self.traffic_generator.get_attack_duration(attack.severity)
        attack.last_detected = datetime.now()
        attack.detection_count += 1
        
        # Generate attack traffic
        attack_traffic = self.traffic_generator.generate_attack_traffic(attack.protocol, attack.severity)
        
        # Create alert
        self.add_alert(
            f"{attack.name} detected on {target.asset_id}",
            target.asset_id,
            attack.severity,
            protocol=attack.protocol,
            indicators=attack.indicators,
            mitigation=attack.mitigation,
            cve=attack.cve,
            attacker_ip=f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        )
        
        # Update target asset status
        target.status = "Under Attack"
        self.refresh_assets()
        
        # Simulate attack traffic
        start_time = time.time()
        while time.time() - start_time < duration and self.running:
            self.protocol_traffic[attack.protocol].append(attack_traffic)
            time.sleep(0.5)
        
        # Reset after attack
        target.status = "Compromised" if random.random() < 0.3 else "Normal"
        self.refresh_assets()
        self.current_attack = None
        self.attack_in_progress = False
    
    def update_asset_statuses(self):
        """Periodically update asset statuses based on network conditions"""
        for asset in self.assets:
            # Skip if already in a bad state
            if asset.status in ["Under Attack", "Compromised", "Isolated"]:
                continue
            
            # Check protocol traffic for anomalies
            traffic = self.protocol_traffic.get(asset.protocol, [])
            if not traffic:
                continue
                
            avg_traffic = sum(traffic) / len(traffic)
            last_traffic = traffic[-1]
            
            # Mark as warning if traffic spikes
            if last_traffic > 2 * avg_traffic:
                asset.status = "Warning"
            else:
                asset.status = "Normal"
        
        # Refresh UI periodically
        if random.random() < 0.1:  # 10% chance to refresh
            self.refresh_assets()
    
    def train_ai_models(self):
        """Train the AI models with simulated data"""
        while self.running:
            try:
                if not self.models_trained:
                    # Generate training data
                    X = np.random.rand(100, 5)  # 100 samples, 5 features
                    y = np.random.randint(0, 2, 100)  # Binary classification
                    
                    # Train models
                    for name, model in self.ai_models.items():
                        if name != "DBSCAN":  # DBSCAN is unsupervised
                            model.fit(X, y)
                        else:
                            model.fit(X)
                    
                    self.models_trained = True
                    self.add_alert(
                        "AI models training completed",
                        "System",
                        "Low",
                        mitigation=["Verify model performance", "Review detection rules"]
                    )
                
                time.sleep(10)
                
            except Exception as e:
                print(f"Error in model training: {e}")
                time.sleep(5)
    
    def detect_anomalies(self):
        """Run anomaly detection using AI models"""
        while self.running:
            try:
                if self.models_trained:
                    # Generate sample data
                    X = np.random.rand(10, 5)  # 10 samples, 5 features
                    
                    # Get predictions from each model
                    for name, model in self.ai_models.items():
                        if name == "DBSCAN":
                            pred = model.fit_predict(X)
                            anomalies = sum(pred == -1)  # -1 indicates anomaly in DBSCAN
                        else:
                            pred = model.predict(X)
                            anomalies = sum(pred == 1)  # 1 indicates anomaly in other models
                        
                        if anomalies > 2:  # If more than 2 anomalies detected
                            self.add_alert(
                                f"{anomalies} anomalies detected by {name}",
                                "Anomaly Detection",
                                "Medium",
                                mitigation=["Review network traffic", "Verify system behavior"]
                            )
                
                time.sleep(5)
                
            except Exception as e:
                print(f"Error in anomaly detection: {e}")
                time.sleep(5)
    
    def monitor_asset_health(self):
        """Monitor asset health and generate alerts"""
        while self.running:
            try:
                for asset in self.assets:
                    # Random health events
                    if random.random() < 0.01:  # 1% chance of health event
                        event = random.choice([
                            "high CPU usage", "memory leak", "network latency",
                            "disk full", "process crash", "connection timeout"
                        ])
                        
                        severity = random.choice(["Low", "Medium", "High"])
                        if asset.criticality == "Critical":
                            severity = random.choice(["High", "Critical"])
                        
                        self.add_alert(
                            f"{asset.asset_id} experiencing {event}",
                            asset.asset_id,
                            severity,
                            mitigation=["Check system logs", "Restart service if needed"]
                        )
                
                time.sleep(10)
                
            except Exception as e:
                print(f"Error in health monitoring: {e}")
                time.sleep(5)
    
    def generate_report(self):
        """Generate a PDF security report"""
        try:
            report = PDFReport()
            report.add_page()
            
            # Report header
            report.set_font('Arial', 'B', 16)
            report.cell(0, 10, 'Industrial Security Assessment Report', 0, 1, 'C')
            report.ln(10)
            
            # System information
            report.chapter_title('System Information')
            report.chapter_body(f"Facility: {self.facility}\nOperator: {self.operator}\nSystem ID: {self.system_id}\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Asset summary
            report.chapter_title('Asset Summary')
            asset_data = [
                ['ID', 'Type', 'IP', 'Protocol', 'Criticality'],
                *[(a.asset_id, a.asset_type, a.ip_address, a.protocol, a.criticality) 
                  for a in sorted(self.assets, key=lambda x: x.criticality, reverse=True)]
            ]
            report.add_table(asset_data[0], asset_data[1:])
            
            # Vulnerability summary
            report.chapter_title('Vulnerability Summary')
            vuln_data = []
            for asset in self.assets:
                for vuln in asset.vulnerabilities:
                    vuln_data.append([
                        asset.asset_id,
                        vuln['cve_id'],
                        vuln['severity'],
                        vuln['cvss_score'],
                        vuln['status']
                    ])
            
            if vuln_data:
                report.add_table(['Asset', 'CVE ID', 'Severity', 'CVSS', 'Status'], vuln_data)
            else:
                report.chapter_body("No vulnerabilities detected")
            
            # Alert summary
            report.chapter_title('Alert Summary')

# Define headers      
            # Recommendations
            report.chapter_title('Security Recommendations')
            recommendations = [
                "1. Implement network segmentation for critical assets",
                "2. Enable protocol-specific security features",
                "3. Patch systems with known vulnerabilities",
                "4. Review and update firewall rules",
                "5. Conduct regular security awareness training"
            ]
            report.chapter_body('\n'.join(recommendations))
            
            # Save the report
            filename = f"ScureProd_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            report.output(filename)
            
            self.add_alert(
                f"Security report generated: {filename}",
                "Reporting",
                "Low",
                mitigation=["Review report findings", "Implement recommendations"]
            )
            
            messagebox.showinfo("Report Generated", f"Security report saved as {filename}")
            
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate report: {e}")
            print(f"Report Error: {e}")
    
    def run_asset_discovery(self):
        """Simulate asset discovery scan"""
        self.add_alert(
            "Asset discovery scan initiated",
            "Discovery",
            "Low",
            mitigation=["Review discovered assets", "Update inventory"]
        )
        
        # Simulate discovery finding new assets
        if random.random() < 0.5:
            new_assets = random.randint(1, 3)
            for i in range(new_assets):
                asset_types = ["PLC", "HMI", "RTU", "Network Switch"]
                protocols = IndustrialProtocol.all_protocols()
                
                asset = IndustrialAsset(
                    asset_id=f"NEW-{random.randint(100,999)}",
                    asset_type=random.choice(asset_types),
                    ip_address=f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                    protocol=random.choice(protocols),
                    criticality=random.choice(["Low", "Medium", "High"])
                )
                
                self.assets.append(asset)
            
            self.refresh_assets()
            self.add_alert(
                f"Discovered {new_assets} new assets",
                "Discovery",
                "Medium",
                mitigation=["Verify new assets", "Update network diagrams"]
            )
        
        messagebox.showinfo("Discovery Complete", "Asset discovery scan completed")
    
    def run_vulnerability_scan(self):
        """Simulate vulnerability scan"""
        self.add_alert(
            "Vulnerability scan initiated",
            "Scanning",
            "Low",
            mitigation=["Review scan results", "Prioritize remediation"]
        )
        
        # Simulate finding vulnerabilities
        vuln_found = 0
        for asset in self.assets:
            if random.random() < 0.3:  # 30% chance of finding a new vuln
                attack = random.choice(self.attack_patterns)
                if attack.protocol == asset.protocol:
                    asset.add_vulnerability(
                        attack.cve,
                        f"Vulnerable to {attack.name}",
                        attack.severity
                    )
                    vuln_found += 1
        
        if vuln_found:
            self.refresh_assets()
            self.add_alert(
                f"Vulnerability scan found {vuln_found} new issues",
                "Scanning",
                "Medium",
                mitigation=["Review vulnerabilities", "Plan patching schedule"]
            )
        
        messagebox.showinfo("Scan Complete", f"Vulnerability scan completed. Found {vuln_found} new issues.")
    
    def backup_configurations(self):
        """Simulate configuration backup"""
        self.add_alert(
            "Configuration backup initiated",
            "Backup",
            "Low",
            mitigation=["Verify backup integrity", "Store securely"]
        )
        
        # Simulate backup process
        time.sleep(2)
        
        self.add_alert(
            "Configuration backup completed",
            "Backup",
            "Low",
            mitigation=["Test restoration procedure", "Update documentation"]
        )
        
        messagebox.showinfo("Backup Complete", "Device configurations backed up successfully")
    
    def show_threat_intel(self):
        """Display threat intelligence information"""
        intel_window = tk.Toplevel(self.root)
        intel_window.title("Threat Intelligence")
        intel_window.geometry("800x600")
        
        text = scrolledtext.ScrolledText(intel_window, wrap=tk.WORD, width=100, height=30,
                                       font=('Consolas', 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Generate threat intel report
        report = ["=== Industrial Threat Intelligence ===",
                 f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
                 "Known Attack Patterns:"]
        
        for attack in self.attack_patterns:
            report.append(f"\n{attack.name} ({attack.protocol}) - {attack.severity}")
            report.append(f"CVE: {attack.cve}")
            report.append("Indicators:")
            report.extend(f"- {i}" for i in attack.indicators)
            report.append("Mitigation:")
            report.extend(f"- {m}" for m in attack.mitigation)
            report.append("")
        
        text.insert(tk.END, '\n'.join(report))
        text.config(state=tk.DISABLED)
    
    def show_documentation(self):
        """Open documentation in web browser"""
        webbrowser.open("https://www.example.com/scureprod-docs")
    
    def show_about(self):
        """Show about dialog"""
        # Fix psutil.cpu_percent() to get actual usage
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory().percent
        about_text = f"""ScureProd Industrial Cyber Defense Platform
Version 1.0.0

Developed for  Manufacturing
© 2025 Reda Ouzidane 

System ID: {self.system_id}
Python: {platform.python_version()}
OS: {platform.system()} {platform.release()}
CPU: {cpu}% usage
Memory: {mem}% used
"""
        messagebox.showinfo("About ScureProd", about_text)
    
    def new_session(self):
        """Start a new session"""
        if messagebox.askyesno("New Session", "Start a new session? Current data will be lost."):
            self.assets = []
            self.alerts = []
            self.attack_log = []
            self.network_traffic = []
            self.protocol_traffic = {p: deque(maxlen=100) for p in IndustrialProtocol.all_protocols()}
            self.threat_level = 0
            
            self.initialize_sample_assets()
            self.refresh_assets()
            self.refresh_alerts()
            self.update_threat_level()
            
            messagebox.showinfo("New Session", "New session initialized")
    
    def save_session(self):
        """Save current session to file"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if not filename:
                return
                
            data = {
                'assets': [vars(a) for a in self.assets],
                'alerts': self.alerts,
                'threat_level': self.threat_level,
                'system_id': self.system_id,
                'operator': self.operator,
                'facility': self.facility
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            messagebox.showinfo("Session Saved", f"Session saved to {filename}")
            
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save session: {e}")
            print(f"Save Error: {e}")
    
    def load_session(self):
        """Load session from file"""
        try:
            filename = filedialog.askopenfilename(
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if not filename:
                return
                
            with open(filename, 'r') as f:
                data = json.load(f)
            
            # Restore assets
            self.assets = []
            for asset_data in data.get('assets', []):
                asset = IndustrialAsset(
                    asset_id=asset_data['asset_id'],
                    asset_type=asset_data['asset_type'],
                    ip_address=asset_data['ip_address'],
                    protocol=asset_data['protocol'],
                    criticality=asset_data['criticality']
                )
                
                # Restore additional attributes
                for key, value in asset_data.items():
                    if key not in ['asset_id', 'asset_type', 'ip_address', 'protocol', 'criticality']:
                        setattr(asset, key, value)
                
                self.assets.append(asset)
            
            # Restore alerts
            self.alerts = data.get('alerts', [])
            
            # Restore system info
            self.system_id = data.get('system_id', str(uuid.uuid4())[:8])
            self.operator = data.get('operator', "Industrial Security Operator")
            self.facility = data.get('facility', "ACME Manufacturing Plant")
            self.threat_level = data.get('threat_level', 0)
            
            # Refresh UI
            self.refresh_assets()
            self.refresh_alerts()
            self.update_threat_level()
            
            messagebox.showinfo("Session Loaded", f"Session loaded from {filename}")
            
        except Exception as e:
            messagebox.showerror("Load Error", f"Failed to load session: {e}")
            print(f"Load Error: {e}")
    
    def on_close(self):
        """Handle application close"""
        if messagebox.askokcancel("Quit", "Do you want to quit ScureProd?"):
            self.running = False
            self.root.destroy()

    def create_heatmap3d_panel(self, parent):
        import numpy as np
        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
        from mpl_toolkits.mplot3d import Axes3D
        from tkinter import filedialog
        # Fullscreen frame
        parent.pack_propagate(False)
        parent.pack(fill=tk.BOTH, expand=True)
        # 3D data
        self.heatmap_grid_size = 50
        self.heatmap_data = np.random.rand(self.heatmap_grid_size, self.heatmap_grid_size) * 100
        X = np.arange(0, self.heatmap_grid_size)
        Y = np.arange(0, self.heatmap_grid_size)
        X, Y = np.meshgrid(X, Y)
        fig = plt.figure(figsize=(12, 8))
        ax = fig.add_subplot(111, projection='3d')
        surf = ax.plot_surface(X, Y, self.heatmap_data, cmap='plasma', edgecolor='none', antialiased=True)
        fig.colorbar(surf, ax=ax, shrink=0.6, aspect=10, label='Threat/Activity Level')
        ax.set_title('3D Threat/Activity Heatmap', color=self.accent_color, fontsize=16, pad=18)
        ax.set_xticks([])
        ax.set_yticks([])
        ax.set_zticks([])
        # 3D model overlay (optional)
        self.model_loaded = False
        def upload_model():
            file_path = filedialog.askopenfilename(filetypes=[("3D Model Files", "*.stl *.obj")])
            if file_path:
                try:
                    import trimesh
                    mesh = trimesh.load(file_path)
                    ax.clear()
                    # Plot the mesh (wireframe for speed)
                    ax.plot_trisurf(mesh.vertices[:,0], mesh.vertices[:,1], mesh.vertices[:,2], color='gray', alpha=0.3, linewidth=0.2, edgecolor='k')
                    # Re-plot the heatmap
                    surf = ax.plot_surface(X, Y, self.heatmap_data, cmap='plasma', edgecolor='none', antialiased=True, alpha=0.7)
                    fig.colorbar(surf, ax=ax, shrink=0.6, aspect=10, label='Threat/Activity Level')
                    ax.set_title('3D Threat/Activity Heatmap + Model', color=self.accent_color, fontsize=16, pad=18)
                    ax.set_xticks([])
                    ax.set_yticks([])
                    ax.set_zticks([])
                    self.model_loaded = True
                    canvas.draw()
                except Exception as e:
                    messagebox.showerror("3D Model Error", f"Failed to load 3D model: {e}")
        # Canvas
        canvas = FigureCanvasTkAgg(fig, master=parent)
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=0, pady=0)
        canvas.draw()
        # Controls
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=8)
        upload_btn = ttk.Button(btn_frame, text="Upload 3D Model (STL/OBJ)", command=upload_model, style='TButton')
        upload_btn.pack(side=tk.LEFT, padx=10)
        def refresh_heatmap():
            self.heatmap_data = np.random.rand(self.heatmap_grid_size, self.heatmap_grid_size) * 100
            ax.clear()
            if self.model_loaded:
                # Re-plot model if loaded
                pass  # For simplicity, re-upload to update
            surf = ax.plot_surface(X, Y, self.heatmap_data, cmap='plasma', edgecolor='none', antialiased=True)
            fig.colorbar(surf, ax=ax, shrink=0.6, aspect=10, label='Threat/Activity Level')
            ax.set_title('3D Threat/Activity Heatmap', color=self.accent_color, fontsize=16, pad=18)
            ax.set_xticks([])
            ax.set_yticks([])
            ax.set_zticks([])
            canvas.draw()
        refresh_btn = ttk.Button(btn_frame, text="🔄 Refresh Heatmap", command=refresh_heatmap, style='TButton')
        refresh_btn.pack(side=tk.LEFT, padx=10)
        # Live update
        def live_update():
            self.heatmap_data *= 0.95
            surf.remove()
            surf2 = ax.plot_surface(X, Y, self.heatmap_data, cmap='plasma', edgecolor='none', antialiased=True)
            canvas.draw()
            parent.after(2000, live_update)
        live_update()
    # --- AI Chatbot Panel ---
    def create_chatbot_panel(self, parent):
        import threading
        openai.api_key = "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"  # Keep this key private!
        # --- Cool Chatbot UI ---
        chat_frame = tk.Frame(parent, bg=self.card_color, bd=2, relief=tk.RIDGE, highlightbackground=self.accent_color, highlightthickness=2)
        chat_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)
        # Header
        header = tk.Label(chat_frame, text="🤖 ScureProd AI Assistant", bg=self.card_color, fg=self.accent_color, font=(self.font_family, 16, 'bold'), pady=10)
        header.pack(fill=tk.X)
        # Chat display area
        chat_display = scrolledtext.ScrolledText(chat_frame, wrap=tk.WORD, height=20, state=tk.NORMAL, bg="#181a20", fg="#eaf6fb", font=(self.font_family, 13), bd=0, relief=tk.FLAT, padx=12, pady=12)
        chat_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        chat_display.tag_configure('user', foreground='#5ad1ff', font=(self.font_family, 13, 'bold'))
        chat_display.tag_configure('ai', foreground=self.accent_color, font=(self.font_family, 13, 'bold'))
        chat_display.tag_configure('system', foreground='#888', font=(self.font_family, 12, 'italic'))
        # Input area
        input_frame = tk.Frame(chat_frame, bg=self.card_color)
        input_frame.pack(fill=tk.X, pady=5)
        user_input = tk.Entry(input_frame, font=(self.font_family, 13), bg="#232634", fg="#eaf6fb", bd=0, relief=tk.FLAT, insertbackground=self.accent_color)
        user_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0), ipady=8, pady=8)
        user_input.config(highlightbackground=self.accent_color, highlightcolor=self.accent_color, highlightthickness=1)
        send_btn = tk.Button(input_frame, text="Send", font=(self.font_family, 12, 'bold'), bg=self.accent_color, fg="#fff", bd=0, relief=tk.FLAT, activebackground="#a084ff", activeforeground="#fff", cursor="hand2", command=lambda: send_message())
        send_btn.pack(side=tk.RIGHT, padx=10, ipadx=16, ipady=6)
        clear_btn = tk.Button(input_frame, text="Clear", font=(self.font_family, 12), bg="#353b48", fg="#fff", bd=0, relief=tk.FLAT, activebackground="#232634", activeforeground="#fff", cursor="hand2", command=lambda: clear_chat())
        clear_btn.pack(side=tk.RIGHT, padx=6, ipadx=10, ipady=6)
        # Typing animation label
        typing_label = tk.Label(chat_frame, text="", bg=self.card_color, fg=self.accent_color, font=(self.font_family, 12, 'italic'))
        typing_label.pack(pady=(0, 5))
        conversation = []
        def clear_chat():
            chat_display.config(state=tk.NORMAL)
            chat_display.delete(1.0, tk.END)
            chat_display.config(state=tk.NORMAL)
            conversation.clear()
        def send_message():
            msg = user_input.get().strip()
            if not msg:
                return
            chat_display.config(state=tk.NORMAL)
            chat_display.insert(tk.END, f"You: {msg}\n", 'user')
            chat_display.see(tk.END)
            user_input.delete(0, tk.END)
            conversation.append({"role": "user", "content": msg})
            typing_label.config(text="AI is typing")
            animate_typing()
            send_btn.config(state=tk.DISABLED)
            user_input.config(state=tk.DISABLED)
            # Run OpenAI call in a background thread
            def get_response():
                try:
                    response = openai.ChatCompletion.create(
                        model="gpt-3.5-turbo",
                        messages=conversation
                    )
                    reply = response.choices[0].message['content']
                except Exception as e:
                    reply = f"[Error: {e}]"
                def update_ui():
                    conversation.append({"role": "assistant", "content": reply})
                    chat_display.config(state=tk.NORMAL)
                    chat_display.insert(tk.END, f"AI: {reply}\n", 'ai')
                    chat_display.see(tk.END)
                    typing_label.config(text="")
                    send_btn.config(state=tk.NORMAL)
                    user_input.config(state=tk.NORMAL)
                self.root.after(0, update_ui)
            threading.Thread(target=get_response, daemon=True).start()
        # Typing animation (animated dots)
        typing_anim = ["AI is typing", "AI is typing.", "AI is typing..", "AI is typing..."]
        def animate_typing(idx=0):
            if typing_label.cget("text") == "":
                return
            typing_label.config(text=typing_anim[idx % len(typing_anim)])
            self.root.after(400, lambda: animate_typing(idx+1))
        user_input.bind('<Return>', lambda event: send_message())

    def create_heatmap_panel(self, parent):
        import numpy as np
        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
        from PIL import Image
        from tkinter import filedialog
        import csv

        # Load your plant map (export SVG as PNG from Inkscape)
        bg_img = np.array(Image.open('plant_map.png'))  # Replace with your PNG file

        # Default: random demo data
        self.points = np.array([[100, 200], [150, 250], [300, 400], [400, 100], [250, 350]])
        self.values = np.array([70, 80, 90, 60, 85])

        def load_csv_data():
            file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
            if not file_path:
                return
            points = []
            values = []
            with open(file_path, newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    points.append([float(row['x']), float(row['y'])])
                    values.append(float(row['value']))
            self.points = np.array(points)
            self.values = np.array(values)
            update_heatmap()

        def update_heatmap():
            heatmap, xedges, yedges = np.histogram2d(
                self.points[:,0], self.points[:,1],
                bins=(bg_img.shape[1]//10, bg_img.shape[0]//10),
                weights=self.values, normed=False)
            heatmap = np.rot90(heatmap)
            heatmap = np.flipud(heatmap)
            hm.set_data(heatmap)
            canvas.draw()

        fig, ax = plt.subplots(figsize=(12, 8))
        ax.imshow(bg_img, extent=[0, bg_img.shape[1], 0, bg_img.shape[0]])
        heatmap, xedges, yedges = np.histogram2d(
            self.points[:,0], self.points[:,1],
            bins=(bg_img.shape[1]//10, bg_img.shape[0]//10),
            weights=self.values, normed=False)
        heatmap = np.rot90(heatmap)
        heatmap = np.flipud(heatmap)
        hm = ax.imshow(heatmap, cmap='hot', alpha=0.5, extent=[0, bg_img.shape[1], 0, bg_img.shape[0]])
        fig.colorbar(hm, ax=ax, label='Measurement')
        ax.axis('off')
        ax.set_title('Live Plant Heatmap', fontsize=20, color='#ff3860', pad=22)

        canvas = FigureCanvasTkAgg(fig, master=parent)
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=0, pady=0)
        canvas.draw()

        # Tooltip on hover
        annot = ax.annotate("", xy=(0,0), xytext=(20,20), textcoords="offset points",
                            bbox=dict(boxstyle="round", fc="w"),
                            arrowprops=dict(arrowstyle="->"))
        annot.set_visible(False)
        def update_annot(ind):
            idx = ind["ind"][0]
            pos = self.points[idx]
            score = self.values[idx]
            annot.xy = pos
            text = f"Machine #{idx+1}\nValue: {score}"
            annot.set_text(text)
            annot.get_bbox_patch().set_facecolor('#232634')
            annot.get_bbox_patch().set_alpha(0.8)
        def hover(event):
            vis = annot.get_visible()
            if event.inaxes == ax:
                cont, ind = hm.contains(event)
                if cont:
                    update_annot(ind)
                    annot.set_visible(True)
                    canvas.draw_idle()
                else:
                    if vis:
                        annot.set_visible(False)
                        canvas.draw_idle()
        fig.canvas.mpl_connect("motion_notify_event", hover)

        # Add Load Data button
        btn_frame = tk.Frame(parent, bg="#232634")
        btn_frame.pack(fill=tk.X, pady=10)
        load_btn = tk.Button(btn_frame, text="📂 Load Data (CSV)", font=(self.font_family, 12, 'bold'), bg="#7f5fff", fg="#fff", bd=0, relief=tk.FLAT, activebackground="#a084ff", activeforeground="#fff", cursor="hand2", command=load_csv_data)
        load_btn.pack(side=tk.LEFT, padx=10, ipadx=12, ipady=6)

        # Live update (optional, for demo)
        def live_update():
            # Simulate new data (replace with real-time updates)
            self.values = np.random.randint(60, 100, len(self.points))
            update_heatmap()
            parent.after(3000, live_update)
        live_update()

    def create_metrics_panel(self, parent):
        import psutil
        import time

        metrics_frame = tk.Frame(parent, bg=self.card_color)
        metrics_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)

        # Title
        title = tk.Label(metrics_frame, text="📊 Industry Metrics", bg=self.card_color, fg=self.accent_color, font=(self.font_family, 18, 'bold'))
        title.pack(pady=(0, 20))

        # Metrics cards
        card_style = {'bg': '#232634', 'fg': '#eaf6fb', 'font': (self.font_family, 16, 'bold'), 'bd': 0, 'relief': tk.FLAT, 'width': 18, 'height': 2}
        card_frame = tk.Frame(metrics_frame, bg=self.card_color)
        card_frame.pack(pady=10)

        # Asset metrics
        total_assets = len(self.assets)
        critical_assets = len([a for a in self.assets if a.criticality == "Critical"])
        isolated_assets = len([a for a in self.assets if a.status == "Isolated"])
        under_attack = len([a for a in self.assets if a.status == "Under Attack"])

        tk.Label(card_frame, text=f"🖥️ Total Assets\n{total_assets}", **card_style).grid(row=0, column=0, padx=16, pady=8)
        tk.Label(card_frame, text=f"🔥 Critical Assets\n{critical_assets}", **card_style).grid(row=0, column=1, padx=16, pady=8)
        tk.Label(card_frame, text=f"🛡️ Isolated\n{isolated_assets}", **card_style).grid(row=0, column=2, padx=16, pady=8)
        tk.Label(card_frame, text=f"⚠️ Under Attack\n{under_attack}", **card_style).grid(row=0, column=3, padx=16, pady=8)

        # Alert metrics
        total_alerts = len(self.alerts)
        critical_alerts = len([a for a in self.alerts if a['severity'] == "Critical"])
        high_alerts = len([a for a in self.alerts if a['severity'] == "High"])
        medium_alerts = len([a for a in self.alerts if a['severity'] == "Medium"])
        low_alerts = len([a for a in self.alerts if a['severity'] == "Low"])

        tk.Label(card_frame, text=f"🚨 Alerts\n{total_alerts}", **card_style).grid(row=1, column=0, padx=16, pady=8)
        tk.Label(card_frame, text=f"🔴 Critical\n{critical_alerts}", **card_style).grid(row=1, column=1, padx=16, pady=8)
        tk.Label(card_frame, text=f"🟠 High\n{high_alerts}", **card_style).grid(row=1, column=2, padx=16, pady=8)
        tk.Label(card_frame, text=f"🟡 Medium\n{medium_alerts}", **card_style).grid(row=1, column=3, padx=16, pady=8)
        tk.Label(card_frame, text=f"🟢 Low\n{low_alerts}", **card_style).grid(row=1, column=4, padx=16, pady=8)

        # System health
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        uptime = int(time.time() - psutil.boot_time()) // 60

        tk.Label(card_frame, text=f"🧠 CPU\n{cpu}%", **card_style).grid(row=2, column=0, padx=16, pady=8)
        tk.Label(card_frame, text=f"💾 Memory\n{mem}%", **card_style).grid(row=2, column=1, padx=16, pady=8)
        tk.Label(card_frame, text=f"⏱️ Uptime\n{uptime} min", **card_style).grid(row=2, column=2, padx=16, pady=8)

        # Optionally, add more cards for vulnerabilities, traffic, etc.

# Main entry point
if __name__ == "__main__":
    root = tk.Tk()
    app = ScureProdApp(root)
    root.mainloop()