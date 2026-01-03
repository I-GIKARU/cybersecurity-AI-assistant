import streamlit as st
import plotly.graph_objects as go
import json
from components.data_service import execute_security_command

def show_threat_intelligence():
    """Threat intelligence page"""
    st.header("🔍 Threat Intelligence")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🌐 Global Threat Feed")
        st.info("Real-time threat intelligence feeds")
        
        if st.button("📊 Generate Report"):
            result = execute_security_command("generate security report")
            if result:
                st.success("✅ Report generated!")
                st.json(result)
    
    with col2:
        st.subheader("🎯 IOC Analysis")
        ioc_input = st.text_input("Enter IOC:", placeholder="IP, domain, hash")
        if st.button("🔍 Analyze") and ioc_input:
            st.success(f"Analyzing {ioc_input}...")

def show_incident_response():
    """Incident response page"""
    st.header("⚡ Incident Response")
    
    st.subheader("🛠️ Response Tools")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔒 Quarantine File"):
            result = execute_security_command("execute real incident response for critical malware detection")
            if result:
                st.success("✅ File quarantined!")
                st.json(result)
    
    with col2:
        if st.button("🚫 Block IP"):
            result = execute_security_command("block malicious IP address")
            if result:
                st.success("✅ IP blocked!")
    
    with col3:
        if st.button("🔄 Reset Firewall"):
            result = execute_security_command("reset firewall rules")
            if result:
                st.success("✅ Firewall reset!")

def show_security_reports():
    """Security reports page"""
    st.header("📋 Security Reports")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Generate Report")
        report_type = st.selectbox("Report Type:", ["Executive Summary", "Technical Analysis", "Compliance Report"])
        time_range = st.selectbox("Time Range:", ["Last 24 Hours", "Last Week", "Last Month"])
        
        if st.button("📋 Generate Report"):
            with st.spinner("Generating report..."):
                result = execute_security_command("generate security report")
                if result:
                    st.success("✅ Report generated!")
                    if isinstance(result.get("response"), str):
                        try:
                            report_data = json.loads(result["response"])
                            st.json(report_data)
                        except:
                            st.text_area("Report:", result.get("response", ""), height=300)
    
    with col2:
        st.subheader("📈 Report History")
        st.info("Previous reports listed here")

def show_system_health(dashboard_data):
    """System health page"""
    st.header("🛠️ System Health")
    
    if not dashboard_data:
        st.error("❌ Unable to fetch system data")
        return
    
    system_status = dashboard_data.get("system_metrics", {})
    
    # System gauges
    col1, col2, col3 = st.columns(3)
    
    with col1:
        cpu_usage = system_status.get("cpu_percent", 0)
        fig = go.Figure(go.Indicator(
            mode="gauge+number", value=cpu_usage, title={'text': "CPU Usage (%)"},
            gauge={'axis': {'range': [None, 100]}, 'bar': {'color': "darkblue"},
                   'steps': [{'range': [0, 50], 'color': "lightgray"}, {'range': [50, 80], 'color': "yellow"}],
                   'threshold': {'line': {'color': "red", 'width': 4}, 'thickness': 0.75, 'value': 90}}
        ))
        fig.update_layout(height=300, font={'color': "white"}, paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        memory_usage = system_status.get("memory_percent", 0)
        fig = go.Figure(go.Indicator(
            mode="gauge+number", value=memory_usage, title={'text': "Memory Usage (%)"},
            gauge={'axis': {'range': [None, 100]}, 'bar': {'color': "darkgreen"},
                   'steps': [{'range': [0, 50], 'color': "lightgray"}, {'range': [50, 80], 'color': "yellow"}],
                   'threshold': {'line': {'color': "red", 'width': 4}, 'thickness': 0.75, 'value': 90}}
        ))
        fig.update_layout(height=300, font={'color': "white"}, paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)
    
    with col3:
        disk_usage = system_status.get("disk_usage", 0)
        fig = go.Figure(go.Indicator(
            mode="gauge+number", value=disk_usage, title={'text': "Disk Usage (%)"},
            gauge={'axis': {'range': [None, 100]}, 'bar': {'color': "darkorange"},
                   'steps': [{'range': [0, 50], 'color': "lightgray"}, {'range': [50, 80], 'color': "yellow"}],
                   'threshold': {'line': {'color': "red", 'width': 4}, 'thickness': 0.75, 'value': 90}}
        ))
        fig.update_layout(height=300, font={'color': "white"}, paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)
    
    # Network and system status
    st.subheader("🌐 System Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Network Connections", system_status.get("network_connections", 0))
        st.metric("Running Processes", system_status.get("active_processes", 0))
    
    with col2:
        st.metric("Logged Users", system_status.get("logged_users", 0))
        st.metric("Open Files", system_status.get("open_files", 0))
    
    with col3:
        st.metric("Root Processes", system_status.get("root_processes", 0))
        st.metric("Failed Logins", system_status.get("failed_logins", 0))
    
    with col4:
        st.metric("Suspicious Ports", system_status.get("suspicious_ports", 0))
        load_avg = system_status.get("load_average", {})
        st.metric("Load Average (1m)", f"{load_avg.get('1min', 0)}")
    
    # System information details
    st.subheader("📊 Detailed System Information")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**🕐 System Uptime**")
        uptime = system_status.get("uptime", "Unknown")
        st.code(uptime)
        
        st.markdown("**💾 Memory Details**")
        memory_percent = system_status.get("memory_percent", 0)
        st.write(f"Memory Usage: {memory_percent}%")
        if "memory" in system_status:
            st.code(system_status["memory"])
        
        st.markdown("**🌐 Network I/O**")
        network_io = system_status.get("network_io", {})
        sent_mb = network_io.get("bytes_sent", 0) / 1024 / 1024
        recv_mb = network_io.get("bytes_recv", 0) / 1024 / 1024
        st.write(f"📤 Sent: {sent_mb:.1f} MB")
        st.write(f"📥 Received: {recv_mb:.1f} MB")
    
    with col2:
        st.markdown("**🖥️ CPU Information**")
        cpu_percent = system_status.get("cpu_percent", 0)
        st.write(f"CPU Usage: {cpu_percent}%")
        if "cpu_cores" in system_status:
            st.write(f"CPU Cores: {system_status['cpu_cores']}")
        
        st.markdown("**💿 Disk Information**")
        disk_usage = system_status.get("disk_usage", 0)
        st.write(f"Disk Usage: {disk_usage}%")
        if "disk_usage_details" in system_status:
            st.code(system_status["disk_usage_details"])
        
        st.markdown("**⚖️ Load Average**")
        load_avg = system_status.get("load_average", {})
        st.write(f"1 min: {load_avg.get('1min', 0)}")
        st.write(f"5 min: {load_avg.get('5min', 0)}")
        st.write(f"15 min: {load_avg.get('15min', 0)}")
    
    # Data collection method info
    if "collection_method" in system_status:
        method = system_status["collection_method"]
        if method == "psutil":
            st.success("📊 Data collected via psutil (high accuracy)")
        elif method == "fallback_real_data":
            st.warning("📊 Data collected via system commands (medium accuracy)")
        elif method == "minimal_fallback":
            st.error("📊 Using minimal fallback data (low accuracy)")
    
    # Timestamp
    timestamp = dashboard_data.get("timestamp", "Unknown")
    if timestamp != "Unknown":
        from datetime import datetime
        try:
            dt = datetime.fromisoformat(timestamp)
            formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
            st.caption(f"Last updated: {formatted_time}")
        except:
            st.caption(f"Last updated: {timestamp}")
    else:
        st.caption(f"Last updated: {timestamp}")
