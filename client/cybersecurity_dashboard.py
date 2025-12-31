import streamlit as st
import requests
import json
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import sqlite3
from services.api_client import CybersecurityAgentAPI

# Page config
st.set_page_config(
    page_title="🔒 Cybersecurity Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark theme
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #0f0f0f 0%, #1a1a1a 100%);
        padding: 1rem;
        border-radius: 10px;
        border: 2px solid #00ff00;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: #1a1a1a;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #00ff00;
        margin: 0.5rem 0;
    }
    .threat-critical { border-left-color: #ff0000 !important; }
    .threat-high { border-left-color: #ff6600 !important; }
    .threat-medium { border-left-color: #ffff00 !important; }
    .threat-low { border-left-color: #00ff00 !important; }
    .stAlert > div { background-color: #1a1a1a; border: 1px solid #00ff00; }
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def get_api_client():
    return CybersecurityAgentAPI("http://localhost:8000")

@st.cache_data(ttl=30)  # Cache for 30 seconds
def get_dashboard_data():
    """Fetch real-time dashboard data"""
    try:
        response = requests.post(
            "http://localhost:8000/query",
            json={"message": "show security dashboard"},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            return json.loads(data["response"])
        return None
    except:
        return None

@st.cache_data(ttl=60)
def get_security_events():
    """Fetch security events from database"""
    try:
        conn = sqlite3.connect("/tmp/security_events.db")
        query = """
        SELECT timestamp, event_type, severity, description, status
        FROM security_events 
        WHERE timestamp > datetime('now', '-24 hours')
        ORDER BY timestamp DESC
        LIMIT 100
        """
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1 style="color: #00ff00; text-align: center; margin: 0;">
            🔒 CYBERSECURITY COMMAND CENTER
        </h1>
        <p style="color: #888; text-align: center; margin: 0;">
            Real-Time Threat Monitoring & Incident Response
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Sidebar
    st.sidebar.title("🛡️ Security Operations")
    
    # Auto-refresh toggle
    auto_refresh = st.sidebar.checkbox("🔄 Auto-refresh (30s)", value=True)
    
    # Manual refresh button
    if st.sidebar.button("🔄 Refresh Now"):
        st.cache_data.clear()
        st.rerun()
    
    # Navigation
    page = st.sidebar.selectbox(
        "Navigate to:",
        [
            "🏠 Dashboard Overview",
            "🚨 Live Threat Monitor", 
            "📊 Security Analytics",
            "🔍 Threat Intelligence",
            "⚡ Incident Response",
            "📋 Security Reports",
            "🛠️ System Health"
        ]
    )
    
    # Get real-time data
    dashboard_data = get_dashboard_data()
    events_df = get_security_events()
    
    if page == "🏠 Dashboard Overview":
        show_dashboard_overview(dashboard_data, events_df)
    elif page == "🚨 Live Threat Monitor":
        show_live_threat_monitor(dashboard_data, events_df)
    elif page == "📊 Security Analytics":
        show_security_analytics(events_df)
    elif page == "🔍 Threat Intelligence":
        show_threat_intelligence()
    elif page == "⚡ Incident Response":
        show_incident_response()
    elif page == "📋 Security Reports":
        show_security_reports()
    elif page == "🛠️ System Health":
        show_system_health(dashboard_data)
    
    # Auto-refresh
    if auto_refresh:
        time.sleep(30)
        st.rerun()

def show_dashboard_overview(dashboard_data, events_df):
    st.header("🏠 Security Dashboard Overview")
    
    if not dashboard_data:
        st.error("❌ Unable to connect to security backend")
        return
    
    # Key metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        threat_level = dashboard_data.get("threat_level", "UNKNOWN")
        color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(threat_level, "⚪")
        st.metric(
            label="🎯 Threat Level",
            value=f"{color} {threat_level}",
            delta=None
        )
    
    with col2:
        total_events = dashboard_data.get("summary", {}).get("total_events_24h", 0)
        st.metric(
            label="📊 Events (24h)",
            value=total_events,
            delta=f"+{total_events - 10}" if total_events > 10 else None
        )
    
    with col3:
        system_health = dashboard_data.get("system_health", "UNKNOWN")
        health_color = {"HEALTHY": "🟢", "WARNING": "🟡", "CRITICAL": "🔴"}.get(system_health, "⚪")
        st.metric(
            label="💻 System Health",
            value=f"{health_color} {system_health}",
            delta=None
        )
    
    with col4:
        response_time = dashboard_data.get("response_metrics", {}).get("avg_response_time", 0)
        st.metric(
            label="⚡ Avg Response",
            value=f"{response_time}s",
            delta=f"-{2.5 - response_time:.1f}s" if response_time < 2.5 else None
        )
    
    # Security summary cards
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🚨 Security Events Summary")
        summary = dashboard_data.get("summary", {})
        
        # Create severity breakdown chart
        severity_data = {
            "Severity": ["Critical", "High", "Medium", "Low"],
            "Count": [
                summary.get("critical_events", 0),
                summary.get("high_events", 0),
                summary.get("medium_events", 0),
                summary.get("low_events", 0)
            ],
            "Color": ["#ff0000", "#ff6600", "#ffff00", "#00ff00"]
        }
        
        fig = px.bar(
            severity_data, 
            x="Severity", 
            y="Count",
            color="Color",
            color_discrete_map={color: color for color in severity_data["Color"]},
            title="Events by Severity (24h)"
        )
        fig.update_layout(
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="white"
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("💻 System Status")
        system_status = dashboard_data.get("current_system_status", {})
        
        # System metrics
        metrics = [
            ("CPU Usage", system_status.get("cpu_percent", 0), "%"),
            ("Memory Usage", system_status.get("memory_percent", 0), "%"),
            ("Disk Usage", system_status.get("disk_usage", 0), "%"),
            ("Network Connections", system_status.get("network_connections", 0), ""),
            ("Active Processes", system_status.get("active_processes", 0), ""),
            ("Load Average (1m)", round(system_status.get("load_average", {}).get("1min", 0), 2), ""),
            ("Uptime", system_status.get("uptime", "Unknown"), ""),
            ("Boot Time", system_status.get("boot_time", "Unknown"), ""),
            ("Logged Users", system_status.get("logged_users", 0), ""),
            ("Open Files", system_status.get("open_files", 0), ""),
            ("Network I/O (MB)", f"{system_status.get('network_io', {}).get('bytes_sent', 0) / 1024 / 1024:.1f} ↑ / {system_status.get('network_io', {}).get('bytes_recv', 0) / 1024 / 1024:.1f} ↓", ""),
            ("Suspicious Ports", system_status.get("suspicious_ports", 0), ""),
            ("Failed Logins", system_status.get("failed_logins", 0), ""),
            ("Root Processes", system_status.get("root_processes", 0), "")
        ]
        
        for metric_name, value, unit in metrics:
            # Determine color based on metric type and value
            if "CPU" in metric_name or "Memory" in metric_name or "Disk" in metric_name:
                if isinstance(value, (int, float)):
                    color = "🔴" if value > 80 else "🟡" if value > 60 else "🟢"
                else:
                    color = "⚪"
            elif "Load Average" in metric_name:
                if isinstance(value, (int, float)):
                    color = "🔴" if value > 4 else "🟡" if value > 2 else "🟢"
                else:
                    color = "⚪"
            elif "Suspicious Ports" in metric_name or "Failed Logins" in metric_name:
                if isinstance(value, (int, float)):
                    color = "🔴" if value > 0 else "🟢"
                else:
                    color = "⚪"
            elif "Root Processes" in metric_name:
                if isinstance(value, (int, float)):
                    color = "🟡" if value > 50 else "🟢"
                else:
                    color = "⚪"
            else:
                color = "🟢"
            
            st.write(f"{color} **{metric_name}**: {value}{unit}")
    
    # Recent events
    st.subheader("📋 Recent Security Events")
    recent_events = dashboard_data.get("recent_events", [])
    
    if recent_events:
        for event in recent_events[:5]:
            severity = event.get("severity", "unknown")
            severity_color = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
            
            st.write(f"{severity_color} **{event.get('timestamp', 'N/A')}** - {event.get('type', 'Unknown')}: {event.get('description', 'No description')}")
    else:
        st.info("No recent security events")

def show_live_threat_monitor(dashboard_data, events_df):
    st.header("🚨 Live Threat Monitor")
    
    # Real-time threat feed
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🔴 Active Threats")
        
        # Simulate live threat feed
        threat_placeholder = st.empty()
        
        with threat_placeholder.container():
            if not events_df.empty:
                # Show recent high-severity events
                high_severity = events_df[events_df['severity'].isin(['critical', 'high'])]
                
                for _, event in high_severity.head(10).iterrows():
                    severity_color = "🔴" if event['severity'] == 'critical' else "🟠"
                    st.write(f"{severity_color} **{event['timestamp']}** - {event['event_type']}: {event['description']}")
            else:
                st.success("✅ No active threats detected")
    
    with col2:
        st.subheader("⚡ Quick Actions")
        
        if st.button("🚨 Emergency Lockdown"):
            response = requests.post(
                "http://localhost:8000/query",
                json={"message": "execute real incident response for critical network intrusion"}
            )
            if response.status_code == 200:
                st.success("🔒 Emergency lockdown initiated!")
            else:
                st.error("❌ Failed to initiate lockdown")
        
        if st.button("🔍 Deep Scan"):
            response = requests.post(
                "http://localhost:8000/query",
                json={"message": "scan 127.0.0.1 for vulnerabilities"}
            )
            if response.status_code == 200:
                st.success("🔍 Deep scan started!")
        
        if st.button("📊 Generate Report"):
            response = requests.post(
                "http://localhost:8000/query",
                json={"message": "generate security report"}
            )
            if response.status_code == 200:
                st.success("📋 Report generated!")

def show_security_analytics(events_df):
    st.header("📊 Security Analytics")
    
    if events_df.empty:
        st.info("No security events data available")
        return
    
    # Event timeline
    st.subheader("📈 Event Timeline")
    
    # Convert timestamp to datetime
    events_df['datetime'] = pd.to_datetime(events_df['timestamp'])
    events_df['hour'] = events_df['datetime'].dt.hour
    
    # Hourly event count
    hourly_events = events_df.groupby('hour').size().reset_index(name='count')
    
    fig = px.line(
        hourly_events, 
        x='hour', 
        y='count',
        title="Security Events by Hour",
        labels={'hour': 'Hour of Day', 'count': 'Event Count'}
    )
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="white"
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Event type breakdown
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🎯 Event Types")
        event_types = events_df['event_type'].value_counts()
        
        fig = px.pie(
            values=event_types.values,
            names=event_types.index,
            title="Events by Type"
        )
        fig.update_layout(
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="white"
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("⚠️ Severity Distribution")
        severity_counts = events_df['severity'].value_counts()
        
        fig = px.bar(
            x=severity_counts.index,
            y=severity_counts.values,
            title="Events by Severity",
            color=severity_counts.index,
            color_discrete_map={
                'critical': '#ff0000',
                'high': '#ff6600',
                'medium': '#ffff00',
                'low': '#00ff00'
            }
        )
        fig.update_layout(
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="white"
        )
        st.plotly_chart(fig, use_container_width=True)

def show_threat_intelligence():
    st.header("🔍 Threat Intelligence")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🔍 IOC Lookup")
        indicator = st.text_input("Enter IP, Domain, or Hash:")
        
        if st.button("🔍 Analyze Indicator"):
            if indicator:
                response = requests.post(
                    "http://localhost:8000/query",
                    json={"message": f"check threat intelligence for {indicator}"}
                )
                if response.status_code == 200:
                    data = response.json()
                    result = json.loads(data["response"])
                    
                    st.write(f"**Indicator**: {result.get('indicator')}")
                    st.write(f"**Threat Score**: {result.get('threat_score', 0):.2f}")
                    st.write(f"**Assessment**: {result.get('ai_assessment')}")
                    
                    if result.get('recommended_actions'):
                        st.write("**Recommended Actions**:")
                        for action in result['recommended_actions']:
                            st.write(f"• {action}")
    
    with col2:
        st.subheader("🤖 AI Analysis")
        
        if st.button("🧠 Run AI Anomaly Detection"):
            response = requests.post(
                "http://localhost:8000/query",
                json={"message": "run AI anomaly detection"}
            )
            if response.status_code == 200:
                data = response.json()
                result = json.loads(data["response"])
                
                st.write(f"**Anomalies Detected**: {result.get('anomalies_detected', 0)}")
                st.write(f"**Threat Level**: {result.get('threat_level', 'Unknown')}")
                
                for anomaly in result.get('anomalies', []):
                    st.write(f"🚨 **{anomaly['type']}**: {anomaly['description']}")
        
        if st.button("🔍 Zero-Day Detection"):
            response = requests.post(
                "http://localhost:8000/query",
                json={"message": "detect zero-day exploits"}
            )
            if response.status_code == 200:
                data = response.json()
                result = json.loads(data["response"])
                
                st.write(f"**Zero-Day Candidates**: {result.get('potential_zero_days', 0)}")
                st.write(f"**Confidence Level**: {result.get('confidence_level', 'Unknown')}")
                
                for candidate in result.get('zero_day_candidates', []):
                    st.write(f"⚠️ **Process**: {candidate.get('affected_process')} - Probability: {candidate.get('zero_day_probability', 0):.0%}")
        
        if st.button("🔗 Blockchain Threat Analysis"):
            response = requests.post(
                "http://localhost:8000/query",
                json={"message": "analyze blockchain threats and crypto mining"}
            )
            if response.status_code == 200:
                data = response.json()
                result = json.loads(data["response"])
                
                st.write(f"**Crypto Mining Detected**: {'Yes' if result.get('crypto_mining_detected') else 'No'}")
                st.write(f"**Threat Assessment**: {result.get('threat_assessment', 'Unknown')}")
                
                if result.get('mining_processes'):
                    st.write("**Mining Processes Found**:")
                    for proc in result['mining_processes']:
                        st.write(f"• PID {proc['pid']}: {proc['name']} ({proc['cpu_usage']}% CPU)")
        
        if st.button("📡 Deep Packet Inspection"):
            response = requests.post(
                "http://localhost:8000/query",
                json={"message": "deep packet inspection"}
            )
            if response.status_code == 200:
                data = response.json()
                result = json.loads(data["response"])
                
                st.write(f"**Packets Analyzed**: {result.get('packets_analyzed', 0)}")
                st.write(f"**Suspicious Packets**: {result.get('suspicious_packets', 0)}")
                
                for packet in result.get('suspicious_traffic', []):
                    st.write(f"🚨 **Threat**: {', '.join(packet.get('threat_indicators', []))}")

def show_incident_response():
    st.header("⚡ Incident Response")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🚨 Create Incident")
        
        threat_type = st.selectbox(
            "Threat Type:",
            ["malware_detected", "network_intrusion", "privilege_escalation", "data_breach"]
        )
        
        severity = st.selectbox(
            "Severity:",
            ["critical", "high", "medium", "low"]
        )
        
        target_file = st.text_input("Target File (optional):")
        target_ip = st.text_input("Target IP (optional):")
        
        if st.button("🚀 Execute Response"):
            message = f"execute real incident response for {severity} {threat_type}"
            if target_file:
                message += f" {target_file}"
            if target_ip:
                message += f" and block IP {target_ip}"
            
            response = requests.post(
                "http://localhost:8000/query",
                json={"message": message}
            )
            
            if response.status_code == 200:
                data = response.json()
                result = json.loads(data["response"])
                
                st.success(f"✅ Incident {result.get('incident_id')} created!")
                st.write(f"**Status**: {result.get('status')}")
                st.write(f"**Response Time**: {result.get('response_time_seconds')}s")
                
                if result.get('actions_taken'):
                    st.write("**Actions Taken**:")
                    for action in result['actions_taken']:
                        st.write(f"• {action.get('action', 'Unknown action')}")
    
    with col2:
        st.subheader("📋 Recent Incidents")
        
        # Show quarantined files
        try:
            import os
            quarantine_dir = "/tmp/quarantine"
            if os.path.exists(quarantine_dir):
                files = os.listdir(quarantine_dir)
                st.write(f"**Quarantined Files**: {len(files)}")
                for file in files[:5]:
                    st.write(f"🔒 {file}")
        except:
            st.write("No quarantine data available")

def show_security_reports():
    st.header("📋 Security Reports")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Generate Report")
        
        report_type = st.selectbox(
            "Report Type:",
            ["Executive Summary", "Technical Analysis", "Compliance Report", "Incident Timeline"]
        )
        
        time_range = st.selectbox(
            "Time Range:",
            ["Last 24 Hours", "Last Week", "Last Month", "Custom"]
        )
        
        if st.button("📋 Generate Report"):
            response = requests.post(
                "http://localhost:8000/query",
                json={"message": "generate security report"}
            )
            
            if response.status_code == 200:
                data = response.json()
                result = json.loads(data["response"])
                
                st.success("✅ Report generated successfully!")
                
                # Display the report content
                st.subheader("📊 Security Report")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**Report Details:**")
                    st.write(f"• Generated: {result.get('report_generated', 'N/A')}")
                    st.write(f"• Time Period: {result.get('time_period_hours', 24)} hours")
                    st.write(f"• Total Events: {result.get('total_events', 0)}")
                
                with col2:
                    st.write("**Event Breakdown:**")
                    events_by_severity = result.get('events_by_severity', {})
                    for severity, count in events_by_severity.items():
                        severity_color = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
                        st.write(f"{severity_color} {severity.title()}: {count}")
                
                # Show recommendations if any
                recommendations = result.get('recommendations', [])
                if recommendations:
                    st.write("**🎯 Recommendations:**")
                    for rec in recommendations:
                        st.write(f"• {rec}")
                
                # Show daily trends if any
                daily_trends = result.get('daily_trends', [])
                if daily_trends:
                    st.write("**📈 Daily Trends:**")
                    for trend in daily_trends:
                        st.write(f"• {trend['date']}: {trend['count']} events")
                
                # Download button for JSON report
                report_json = json.dumps(result, indent=2)
                st.download_button(
                    label="📥 Download JSON Report",
                    data=report_json,
                    file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
                
                # Download button for formatted text report
                formatted_report = f"""
CYBERSECURITY REPORT
Generated: {result.get('report_generated', 'N/A')}
Time Period: {result.get('time_period_hours', 24)} hours

SUMMARY:
- Total Events: {result.get('total_events', 0)}
- Events by Severity: {result.get('events_by_severity', {})}
- Events by Type: {result.get('events_by_type', {})}

RECOMMENDATIONS:
{chr(10).join([f"- {rec}" for rec in result.get('recommendations', ['No recommendations at this time'])])}

DAILY TRENDS:
{chr(10).join([f"- {trend['date']}: {trend['count']} events" for trend in result.get('daily_trends', [])])}
                """
                
                st.download_button(
                    label="📄 Download Text Report",
                    data=formatted_report,
                    file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )
    
    with col2:
        st.subheader("📈 Report History & Alerts")
        
        # Show recent alerts
        try:
            import os
            import glob
            
            # Find alert files
            alert_files = glob.glob("/tmp/ALERT-*.json")
            alert_files.sort(key=os.path.getmtime, reverse=True)
            
            if alert_files:
                st.write("**🚨 Recent Alerts:**")
                for alert_file in alert_files[:5]:
                    try:
                        with open(alert_file, 'r') as f:
                            alert_data = json.load(f)
                        
                        alert_id = alert_data.get('alert_id', 'Unknown')
                        severity = alert_data.get('severity', 'unknown')
                        threat_type = alert_data.get('threat_type', 'Unknown')
                        timestamp = alert_data.get('timestamp', 'Unknown')
                        
                        severity_color = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
                        
                        with st.expander(f"{severity_color} {alert_id} - {threat_type}"):
                            st.write(f"**Severity**: {severity}")
                            st.write(f"**Type**: {threat_type}")
                            st.write(f"**Time**: {timestamp}")
                            st.write(f"**Message**: {alert_data.get('message', 'No message')}")
                            
                            if alert_data.get('recommended_actions'):
                                st.write("**Actions**:")
                                for action in alert_data['recommended_actions']:
                                    st.write(f"• {action}")
                            
                            # Download individual alert
                            st.download_button(
                                label="📥 Download Alert",
                                data=json.dumps(alert_data, indent=2),
                                file_name=f"{alert_id}.json",
                                mime="application/json",
                                key=f"download_{alert_id}"
                            )
                    except:
                        continue
            else:
                st.info("No recent alerts found")
            
            # Show quarantined files as evidence
            st.write("**🔒 Quarantined Files:**")
            quarantine_dir = "/tmp/quarantine"
            if os.path.exists(quarantine_dir):
                files = os.listdir(quarantine_dir)
                if files:
                    for file in files[-5:]:  # Show last 5
                        file_path = os.path.join(quarantine_dir, file)
                        try:
                            stat = os.stat(file_path)
                            size = stat.st_size
                            mtime = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                            st.write(f"🔒 **{file}** ({size} bytes) - Quarantined: {mtime}")
                        except:
                            st.write(f"🔒 **{file}** - Access restricted")
                else:
                    st.info("No quarantined files")
            else:
                st.info("Quarantine directory not found")
                
        except Exception as e:
            st.error(f"Error loading reports: {str(e)}")

def show_system_health(dashboard_data):
    st.header("🛠️ System Health")
    
    if not dashboard_data:
        st.error("❌ Unable to fetch system data")
        return
    
    system_status = dashboard_data.get("current_system_status", {})
    
    # System metrics gauges
    col1, col2, col3 = st.columns(3)
    
    with col1:
        cpu_percent = system_status.get("cpu_percent", 0)
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = cpu_percent,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "CPU Usage (%)"},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 50], 'color': "lightgray"},
                    {'range': [50, 80], 'color': "yellow"},
                    {'range': [80, 100], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        fig.update_layout(height=300, font={'color': "white"}, paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        memory_percent = system_status.get("memory_percent", 0)
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = memory_percent,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Memory Usage (%)"},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkgreen"},
                'steps': [
                    {'range': [0, 50], 'color': "lightgray"},
                    {'range': [50, 80], 'color': "yellow"},
                    {'range': [80, 100], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        fig.update_layout(height=300, font={'color': "white"}, paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)
    
    with col3:
        disk_usage = system_status.get("disk_usage", 0)
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = disk_usage,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Disk Usage (%)"},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkorange"},
                'steps': [
                    {'range': [0, 50], 'color': "lightgray"},
                    {'range': [50, 80], 'color': "yellow"},
                    {'range': [80, 100], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        fig.update_layout(height=300, font={'color': "white"}, paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)
    
    # Network connections
    st.subheader("🌐 Network Status")
    connections = system_status.get("network_connections", 0)
    processes = system_status.get("active_processes", 0)
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Active Connections", connections)
    with col2:
        st.metric("Running Processes", processes)

if __name__ == "__main__":
    main()
