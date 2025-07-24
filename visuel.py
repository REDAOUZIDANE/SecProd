import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
from datetime import datetime, timedelta

# =============================================
# 1. INDUSTRIAL FACTORY LAYOUT SIMULATION
# =============================================
factory_length = 200  # meters (large-scale facility)
factory_width = 100   # meters 
height_levels = 6      # floors/industrial racks

# Generate grid with production zones
x = np.linspace(0, factory_length, 80)
y = np.linspace(0, factory_width, 60)
z = np.linspace(0, height_levels, 6)
X, Y, Z = np.meshgrid(x, y, z)

# =============================================
# 2. CYBER-PHYSICAL THREAT MODELING
# =============================================
def generate_threat_surface():
    """Simulates multi-vector industrial threats"""
    base_threat = np.zeros_like(X)
    
    # Production Line Vulnerabilities
    production_lines = [
        {"x": 30, "y": 20, "radius": 15, "threat": 0.8},  # Automotive assembly
        {"x": 120, "y": 60, "radius": 20, "threat": 0.7},  # Packaging robots
        {"x": 180, "y": 30, "radius": 12, "threat": 0.9}   # High-precision CNC
    ]
    
    for line in production_lines:
        dist = np.sqrt((X-line["x"])**2 + (Y-line["y"])**2)
        base_threat += line["threat"] * np.exp(-dist**2/(2*line["radius"]**2))
    
    # Network Infrastructure Risks
    network_hotspots = [
        (50, 80, 0.6),  # OT-DMZ gateway
        (150, 20, 0.7), # SCADA server room
        (90, 40, 0.5)   # Wireless AP cluster
    ]
    
    for xc, yc, threat in network_hotspots:
        base_threat += threat * np.exp(-((X-xc)**2 + (Y-yc)**2)/300)
    
    # Height-based vulnerabilities (ground floor most exposed)
    base_threat *= (1 + 0.3*np.cos(Z*0.5))
    
    # Add random anomalies (emerging threats)
    base_threat += 0.15 * np.random.weibull(0.8, size=X.shape)
    
    return (base_threat - base_threat.min()) / (base_threat.max() - base_threat.min())

threat_heat = generate_threat_surface()

# =============================================
# 3. INDUSTRIAL ASSET DATABASE
# =============================================
assets = pd.DataFrame([
    # Critical OT Devices
    {"id": "PLC_01", "type": "Siemens S7-1500", "x": 32, "y": 22, "z": 1, "threat": 0.85, "status": "compromised"},
    {"id": "HMI_04", "type": "Allen-Bradley PanelView", "x": 125, "y": 62, "z": 1, "threat": 0.72, "status": "anomalous"},
    {"id": "RTU_12", "type": "Schneider Electric", "x": 182, "y": 32, "z": 1, "threat": 0.91, "status": "critical"},
    
    # Network Infrastructure
    {"id": "SCADA_MAIN", "type": "ICS Server", "x": 152, "y": 18, "z": 3, "threat": 0.68, "status": "monitored"},
    {"id": "FW_OT", "type": "Industrial Firewall", "x": 52, "y": 82, "z": 2, "threat": 0.55, "status": "secure"},
    
    # IIoT Devices
    {"id": "DRONE_01", "type": "Inspection UAV", "x": 80, "y": 70, "z": 4, "threat": 0.45, "status": "offline"},
    {"id": "AGV_03", "type": "Autonomous Vehicle", "x": 40, "y": 50, "z": 0, "threat": 0.63, "status": "moving"},
])

# =============================================
# 4. ATTACK SIMULATION VISUALIZATION
# =============================================
fig = go.Figure()

# 3D Threat Volume (Enterprise-Grade Rendering)
fig.add_trace(go.Volume(
    x=X.flatten(),
    y=Y.flatten(),
    z=Z.flatten(),
    value=threat_heat.flatten(),
    isomin=0.3,
    isomax=0.9,
    opacity=0.15,
    surface_count=30,
    colorscale="Portland",
    colorbar=dict(
        title="<b>Threat Index</b>",
        tickvals=[0.3, 0.6, 0.9],
        ticktext=["<b>Low</b>", "<b>Medium</b>", "<b>Critical</b>"],
        x=0.85
    ),
    name="Cyber-Physical Threat Surface"
))

# Asset Visualization with Status Encoding
status_colors = {
    "secure": "green",
    "monitored": "blue",
    "anomalous": "orange",
    "critical": "red",
    "compromised": "purple",
    "offline": "gray",
    "moving": "cyan"
}

# --- Minimal, Clean Banner and Technical Design Elements ---

# Minimal, clean title and banner
fig.update_layout(
    title=dict(
        text="<b>SecureProd OT Threat Dashboard</b>",
        x=0.02,
        y=0.98,
        font=dict(size=22, family="Segoe UI, Arial, sans-serif", color="#E0E0E0"),
        pad=dict(t=10, b=0)
    ),
    margin=dict(l=0, r=0, t=60, b=0),
)

# Remove previous banner annotation if present (skip re-adding branding banner)

# Machine type icons/colors
# Update machine_icons to use only valid 3D marker symbols
machine_icons = {
    "PLC": dict(symbol="diamond", color="#00FFD0"),
    "HMI": dict(symbol="square", color="#FFA500"),
    "Robot": dict(symbol="circle", color="#FF4C4C"),
    "Sensor": dict(symbol="cross", color="#FFD700"),
    "Firewall": dict(symbol="x", color="#00BFFF"),
    "Server": dict(symbol="diamond-open", color="#B266FF"),  # Use diamond-open for server
    "Vehicle": dict(symbol="circle-open", color="#00FF7F"),  # Use circle-open for vehicle
    "UAV": dict(symbol="square-open", color="#CCCCCC"),      # Use square-open for UAV
    "Other": dict(symbol="circle", color="#888888"),
}

# Add technical grid overlay (as faint lines in the 3D scene)
grid_lines = []
for gx in range(0, 201, 20):
    grid_lines.append(go.Scatter3d(
        x=[gx, gx], y=[0, 100], z=[0, 0],
        mode="lines", line=dict(color="rgba(200,200,200,0.08)", width=2), showlegend=False, hoverinfo="skip"
    ))
for gy in range(0, 101, 20):
    grid_lines.append(go.Scatter3d(
        x=[0, 200], y=[gy, gy], z=[0, 0],
        mode="lines", line=dict(color="rgba(200,200,200,0.08)", width=2), showlegend=False, hoverinfo="skip"
    ))
for gz in range(1, 6):
    grid_lines.append(go.Scatter3d(
        x=[0, 200], y=[0, 0], z=[gz, gz],
        mode="lines", line=dict(color="rgba(200,200,200,0.06)", width=1), showlegend=False, hoverinfo="skip"
    ))
for gl in grid_lines:
    fig.add_trace(gl)

# Draw network links between machines (example: PLC to HMI, Server to Firewall, etc.)
network_links = [
    ("PLC_01", "HMI_04"),
    ("PLC_01", "SCADA_MAIN"),
    ("SCADA_MAIN", "FW_OT"),
    ("FW_OT", "RTU_12"),
    ("AGV_03", "PLC_01"),
    ("DRONE_01", "Server"),
]
for src, dst in network_links:
    src_row = assets[assets['id'] == src]
    dst_row = assets[assets['id'] == dst]
    if not src_row.empty and not dst_row.empty:
        fig.add_trace(go.Scatter3d(
            x=[src_row.iloc[0]['x'], dst_row.iloc[0]['x']],
            y=[src_row.iloc[0]['y'], dst_row.iloc[0]['y']],
            z=[src_row.iloc[0]['z'], dst_row.iloc[0]['z']],
            mode="lines",
            line=dict(color="rgba(0,255,208,0.18)", width=6, dash="solid"),
            showlegend=False,
            hoverinfo="skip"
        ))

# Add machines with technical icons/colors
for _, asset in assets.iterrows():
    # Determine machine type
    if "PLC" in asset["id"]:
        icon = machine_icons["PLC"]
    elif "HMI" in asset["id"]:
        icon = machine_icons["HMI"]
    elif "Robot" in asset["type"]:
        icon = machine_icons["Robot"]
    elif "Sensor" in asset["type"]:
        icon = machine_icons["Sensor"]
    elif "Firewall" in asset["type"]:
        icon = machine_icons["Firewall"]
    elif "Server" in asset["type"]:
        icon = machine_icons["Server"]
    elif "Vehicle" in asset["type"]:
        icon = machine_icons["Vehicle"]
    elif "UAV" in asset["type"]:
        icon = machine_icons["UAV"]
    else:
        icon = machine_icons["Other"]
    fig.add_trace(go.Scatter3d(
        x=[asset["x"]],
        y=[asset["y"]],
        z=[asset["z"]],
        mode="markers+text",
        marker=dict(
            size=15,
            color=icon["color"],
            symbol=icon["symbol"],
            line=dict(width=2, color="#222")
        ),
        text=f"{asset['id']}<br>{asset['type']}",
        textposition="top center",
        hoverinfo="text",
        name=asset["id"],
        hovertemplate=(
            f"<b>{asset['id']}</b><br>"
            f"Type: {asset['type']}<br>"
            f"Status: {asset['status'].upper()}<br>"
            f"Threat: {asset['threat']*100:.0f}%<br>"
            f"Location: ({asset['x']}m, {asset['y']}m, Floor {int(asset['z'])})"
            "<extra></extra>"
        )
    ))

# Attack Vectors Simulation
attack_vectors = [
    {"start": (5, 90, 0), "end": (32, 22, 1), "type": "RCE", "time": datetime.now() - timedelta(minutes=5)},
    {"start": (160, 5, 0), "end": (152, 18, 3), "type": "Credential Theft", "time": datetime.now() - timedelta(minutes=12)},
    {"start": (195, 95, 0), "end": (182, 32, 1), "type": "Malware", "time": datetime.now() - timedelta(minutes=8)},
]

for attack in attack_vectors:
    fig.add_trace(go.Scatter3d(
        x=[attack["start"][0], attack["end"][0]],
        y=[attack["start"][1], attack["end"][1]],
        z=[attack["start"][2], attack["end"][2]],
        mode="lines",
        line=dict(width=4, color="red", dash="dot"),
        name=f"{attack['type']} Attack",
        hovertemplate=(
            f"<b>{attack['type']}</b><br>"
            f"Detected: {attack['time'].strftime('%H:%M:%S')}<br>"
            "<extra></extra>"
        )
    ))

# =============================================
# 5. ENTERPRISE-GRADE VISUALIZATION LAYOUT
# =============================================
fig.update_layout(
    title=dict(
        text="<b>SECUREPROD INDUSTRIAL THREAT INTELLIGENCE DASHBOARD</b><br>"
             "<span style='font-size:16px; color:#00FFD0;'>Real-Time Cyber-Physical Risk Mapping for Industry 4.0</span>",
        x=0.5,
        y=0.97,
        font=dict(size=26, family="Arial Black, Arial, sans-serif", color="#00FFD0"),
        pad=dict(t=20, b=10)
    ),
    scene=dict(
        xaxis=dict(title="<b>FACTORY LENGTH (m)</b>", gridcolor="rgba(100,100,100,0.5)", color="#FFFFFF", showbackground=True, backgroundcolor="rgba(0,0,0,0.7)", zerolinecolor="#00FFD0"),
        yaxis=dict(title="<b>FACTORY WIDTH (m)</b>", gridcolor="rgba(100,100,100,0.5)", color="#FFFFFF", showbackground=True, backgroundcolor="rgba(0,0,0,0.7)", zerolinecolor="#00FFD0"),
        zaxis=dict(title="<b>HEIGHT LEVEL</b>", gridcolor="rgba(100,100,100,0.5)", color="#FFFFFF", showbackground=True, backgroundcolor="rgba(0,0,0,0.7)", zerolinecolor="#00FFD0"),
        bgcolor="rgb(10,10,20)",
        camera=dict(
            eye=dict(x=2.2, y=-2.2, z=1.2),
            up=dict(x=0, y=0, z=1)
        ),
        annotations=[
            dict(
                x=160,
                y=10,
                z=3,
                text="<b>ACTIVE RANSOMWARE ATTACK</b>",
                showarrow=True,
                arrowhead=2,
                arrowsize=2,
                ax=50,
                ay=-30,
                font=dict(color="#FF4C4C", size=14, family="Arial Black"),
                bgcolor="#1a1a1a",
                bordercolor="#FF4C4C",
                borderpad=4
            )
        ]
    ),
    margin=dict(l=0, r=0, b=0, t=120),
    legend=dict(
        orientation="h",
        yanchor="bottom",
        y=1.05,
        font=dict(size=13, color="#00FFD0", family="Arial Black"),
        itemsizing="constant",
        bgcolor="rgba(0,0,0,0.7)",
        bordercolor="#00FFD0",
        borderwidth=2
    ),
    hoverlabel=dict(
        bgcolor="rgba(0,0,0,0.95)",
        font=dict(size=13, color="#00FFD0", family="Arial Black")
    ),
    template="plotly_dark",
    width=1400,
    height=900,
    paper_bgcolor="rgb(10,10,20)",
    plot_bgcolor="rgb(10,10,20)"
)

# Add SecureProd branding with a glowing effect
fig.add_annotation(
    x=0.5, y=-0.13, xref="paper", yref="paper",
    text="<b style='color:#00FFD0; text-shadow:0 0 10px #00FFD0;'>SecureProd™ | AI-Powered OT Protection | Industry 4.0 Security Platform</b>",
    showarrow=False,
    font=dict(size=15, color="#00FFD0", family="Arial Black"),
    align="center",
    bordercolor="#00FFD0",
    borderpad=8,
    borderwidth=2,
    bgcolor="rgba(10,10,20,0.8)"
)

# =============================================
# 6. INTERACTIVE CONTROLS & EXPORT
# =============================================
fig.update_layout(
    updatemenus=[
        dict(
            type="buttons",
            direction="left",
            x=0.5,
            y=-0.18,
            xanchor="center",
            yanchor="top",
            bgcolor="#1a1a1a",
            bordercolor="#00FFD0",
            borderwidth=2,
            font=dict(color="#00FFD0", size=13, family="Arial Black"),
            buttons=list([
                dict(
                    args=[{"scene.camera": {"eye": {"x": 2.2, "y": -2.2, "z": 1.2}}}],
                    label="Reset View",
                    method="relayout"
                ),
                dict(
                    args=[{"scene.camera": {"eye": {"x": 0, "y": 0, "z": 2.5}}}],
                    label="Top Down",
                    method="relayout"
                ),
                dict(
                    args=[{"scene.camera": {"eye": {"x": 2.2, "y": 2.2, "z": 1.2}}}],
                    label="Rotate",
                    method="relayout"
                ),
                dict(
                    args=["toImage"],
                    label="Export PNG",
                    method="relayout"
                )
            ])
        )
    ]
)

# For Modbus (pymodbus)
from pymodbus.client import ModbusTcpClient

def poll_modbus(ip, port=502):
    client = ModbusTcpClient(ip, port)
    client.connect()
    rr = client.read_holding_registers(0, 10, unit=1)
    client.close()
    return rr.registers if rr.isError() is False else None

# For OPC UA (opcua)
from opcua import Client

def poll_opcua(endpoint):
    client = Client(endpoint)
    client.connect()
    value = client.get_node("ns=2;i=2").get_value()
    client.disconnect()
    return value

# --- Cross-Browser Compatible, Ultra-Cool Plotly Dashboard ---

# Responsive layout: fill the browser window
fig.update_layout(
    autosize=True,
    width=None,
    height=None,
    margin=dict(l=0, r=0, t=120, b=0),
    paper_bgcolor="rgb(10,10,20)",
    plot_bgcolor="rgb(10,10,20)",
)

# Remove any previous control annotation

# Add a floating, minimal control panel in the top-right corner
fig.add_annotation(
    x=1.01, y=1.01, xref="paper", yref="paper",
    text=(
        "<div style='"
        "background:rgba(20,20,30,0.92);"
        "border-radius:14px;"
        "padding:10px 22px;"
        "box-shadow:0 2px 16px #00FFD044;"
        "display:flex;gap:12px;align-items:center;"
        "font-family:Segoe UI,Arial,sans-serif;"
        "font-size:15px;"
        "color:#00FFD0;"
        "'>"
        "<b>Controls:</b>"
        "<button style='margin-left:10px;padding:7px 16px;border-radius:7px;border:none;"
        "background:#00FFD0;color:#101020;font-size:14px;font-weight:bold;cursor:pointer;"
        "transition:background 0.2s;'>Connect</button>"
        "<button style='margin-left:6px;padding:7px 16px;border-radius:7px;border:none;"
        "background:#222;color:#00FFD0;font-size:14px;font-weight:bold;cursor:pointer;"
        "transition:background 0.2s;'>Refresh</button>"
        "</div>"
    ),
    showarrow=False,
    align="right",
    xanchor="right",
    yanchor="top",
    bordercolor="rgba(0,0,0,0)",
    borderpad=0,
    borderwidth=0,
    bgcolor="rgba(0,0,0,0)"
)

# Add a neon animated loading spinner (as annotation, for demo)
fig.add_annotation(
    x=0.5, y=1.12, xref="paper", yref="paper",
    text=(
        "<svg width='40' height='40' viewBox='0 0 40 40' style='vertical-align:middle;'>"
        "<circle cx='20' cy='20' r='16' stroke='#00FFD0' stroke-width='4' fill='none' "
        "stroke-dasharray='100' stroke-dashoffset='60'>"
        "<animateTransform attributeName='transform' type='rotate' from='0 20 20' to='360 20 20' dur='1s' repeatCount='indefinite'/></circle>"
        "</svg>"
        "<span style='color:#00FFD0;font-family:Arial Black;font-size:15px;margin-left:10px;vertical-align:middle;'>Loading live data...</span>"
    ),
    showarrow=False,
    align="center",
    xanchor="center",
    yanchor="bottom",
    bordercolor="#00FFD0",
    borderpad=4,
    borderwidth=0,
    bgcolor="rgba(0,0,0,0)"
)

# Add subtle neon-glow and smooth marker effects
for trace in fig.data:
    if hasattr(trace, 'marker'):
        trace.marker.line = dict(width=4, color="#00FFD0")
        trace.marker.opacity = 0.96
        trace.marker.sizeref = 1.15

# Show the figure responsively and with a modern toolbar
fig.show(config={
    'responsive': True,
    'displayModeBar': True,
    'displaylogo': False,
    'modeBarButtonsToRemove': ['sendDataToCloud'],
    'toImageButtonOptions': {
        'format': 'png',
        'filename': 'secureprod_dashboard',
        'height': 900,
        'width': 1600,
        'scale': 2
    }
})

# --- Industrial-Ready, Minimal, and Professional Plotly Dashboard ---

# Minimal fixed header (logo + title)
fig.add_annotation(
    x=0, y=1.13, xref="paper", yref="paper",
    text="<span style='font-size:15px;font-family:Segoe UI,Arial,sans-serif;color:#CCCCCC;'>SecureProd OT Dashboard</span>",
    showarrow=False,
    align="left",
    xanchor="left",
    yanchor="top",
    bordercolor="rgba(0,0,0,0)",
    borderpad=0,
    borderwidth=0,
    bgcolor="rgba(0,0,0,0)"
)

# Floating control/status panel (top-right, visual only)
fig.add_annotation(
    x=1.01, y=1.07, xref="paper", yref="paper",  # y increased for more space
    text="""
    <div style='background:rgba(30,30,40,0.97);border-radius:12px;padding:10px 20px;
    box-shadow:0 2px 12px #00AEEF33;display:flex;flex-direction:column;gap:8px;min-width:180px;max-width:260px;'>
    <div style='display:flex;align-items:center;gap:10px;'>
    <span style='font-size:15px;color:#00AEEF;font-family:Segoe UI,Arial,sans-serif;font-weight:bold;'>Controls</span>
    <span style='margin-left:auto;width:14px;height:14px;border-radius:50%;background:#2ECC40;display:inline-block;border:2px solid #222;' title='Connected'></span>
    </div>
    <div style='display:flex;gap:8px;margin-top:2px;'>
    <span style='background:#00AEEF;color:#101020;border-radius:7px;padding:6px 14px;font-size:14px;font-weight:bold;'>Connect</span>
    <span style='background:#222;color:#00AEEF;border-radius:7px;padding:6px 14px;font-size:14px;font-weight:bold;'>Refresh</span>
    </div>
    <div style='margin-top:6px;font-size:13px;color:#BBB;font-family:Segoe UI,Arial;'>
    <b>Config:</b> 192.168.1.10:502 (Modbus)
    </div>
    </div>
    """,
    showarrow=False,
    align="right",
    xanchor="right",
    yanchor="top",
    bordercolor="rgba(0,0,0,0)",
    borderpad=0,
    borderwidth=0,
    bgcolor="rgba(0,0,0,0)"
)

# Colorblind-friendly palette for status
machine_icons = {
    "PLC": dict(symbol="diamond", color="#0072B2"),
    "HMI": dict(symbol="square", color="#E69F00"),
    "Robot": dict(symbol="circle", color="#D55E00"),
    "Sensor": dict(symbol="cross", color="#F0E442"),
    "Firewall": dict(symbol="x", color="#009E73"),
    "Server": dict(symbol="diamond-open", color="#CC79A7"),
    "Vehicle": dict(symbol="circle-open", color="#56B4E9"),
    "UAV": dict(symbol="square-open", color="#999999"),
    "Other": dict(symbol="circle", color="#888888"),
}

# All overlays (grid, links, machines) remain subtle and readable (as before)
# ... rest of your technical overlays and machine plotting code ...

# Remove all banner/title annotations for a fully minimal dashboard
# (No fig.add_annotation for title/banner)
# If you have a fig.update_layout(title=...), set title to an empty string
fig.update_layout(title="")