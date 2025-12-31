import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from components.data_service import execute_security_command

def show_dashboard_overview(dashboard_data, events_df):
    """Dashboard overview page"""
    st.header("🏠 Security Dashboard Overview")
    
    if not dashboard_data:
        st.error("❌ Unable to connect to security backend")
        return
    
    # Key metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        threat_level = dashboard_data.get("threat_level", "UNKNOWN")
        color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(threat_level, "⚪")
        st.metric("🎯 Threat Level", f"{color} {threat_level}")
    
    with col2:
        total_events = dashboard_data.get("summary", {}).get("total_events_24h", 0)
        st.metric("📊 Events (24h)", total_events, delta=f"+{total_events - 10}" if total_events > 10 else None)
    
    with col3:
        system_health = dashboard_data.get("system_health", "UNKNOWN")
        health_color = {"HEALTHY": "🟢", "WARNING": "🟡", "CRITICAL": "🔴"}.get(system_health, "⚪")
        st.metric("💻 System Health", f"{health_color} {system_health}")
    
    with col4:
        response_time = dashboard_data.get("response_metrics", {}).get("avg_response_time", 0)
        st.metric("⚡ Avg Response", f"{response_time}s", delta=f"-{2.5 - response_time:.1f}s" if response_time < 2.5 else None)
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🚨 Security Events Summary")
        summary = dashboard_data.get("summary", {})
        severity_data = {
            "Severity": ["Critical", "High", "Medium", "Low"],
            "Count": [summary.get("critical_events", 0), summary.get("high_events", 0), 
                     summary.get("medium_events", 0), summary.get("low_events", 0)],
            "Color": ["#ff0000", "#ff6600", "#ffff00", "#00ff00"]
        }
        fig = px.bar(severity_data, x="Severity", y="Count", color="Color",
                    color_discrete_map={color: color for color in severity_data["Color"]})
        fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("⚠️ Severity Distribution")
        if not events_df.empty:
            severity_counts = events_df['severity'].value_counts()
            fig = px.pie(values=severity_counts.values, names=severity_counts.index,
                        color_discrete_map={"CRITICAL": "#ff0000", "HIGH": "#ff6600", "MEDIUM": "#ffff00", "LOW": "#00ff00"})
            fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig, use_container_width=True)
    
    # Recent events
    if not events_df.empty:
        st.subheader("🔍 Recent Security Events")
        for _, event in events_df.head(5).iterrows():
            severity_class = f"threat-{event['severity'].lower()}"
            st.markdown(f"""
            <div class="metric-card {severity_class}">
                <strong>{event['event_type']}</strong> - {event['description']}
                <br><small>{event['timestamp']} | {event['severity']} | {event['status']}</small>
            </div>
            """, unsafe_allow_html=True)

def show_live_threat_monitor(dashboard_data, events_df):
    """Live threat monitoring page"""
    st.header("🚨 Live Threat Monitor")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🔴 Active Threats")
        if not events_df.empty:
            high_severity = events_df[events_df['severity'].isin(['CRITICAL', 'HIGH'])]
            for _, event in high_severity.head(10).iterrows():
                severity_color = "🔴" if event['severity'] == 'CRITICAL' else "🟠"
                st.write(f"{severity_color} **{event['timestamp']}** - {event['event_type']}: {event['description']}")
        else:
            st.success("✅ No active threats detected")
    
    with col2:
        st.subheader("⚡ Quick Actions")
        if st.button("🚨 Emergency Lockdown"):
            result = execute_security_command("execute real incident response for critical network intrusion")
            if result:
                st.success("🔒 Emergency lockdown initiated!")
        
        if st.button("🔍 Deep Scan"):
            result = execute_security_command("scan 127.0.0.1 for vulnerabilities")
            if result:
                st.success("🔍 Deep scan started!")

def show_security_analytics(events_df):
    """Security analytics page"""
    st.header("📊 Security Analytics")
    
    if events_df.empty:
        st.info("No data available for analysis")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📈 Event Timeline")
        events_df['datetime'] = pd.to_datetime(events_df['timestamp'])
        timeline_data = events_df.groupby([events_df['datetime'].dt.hour, 'severity']).size().reset_index(name='count')
        fig = px.line(timeline_data, x='datetime', y='count', color='severity')
        fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("⚠️ Event Types")
        event_counts = events_df['event_type'].value_counts()
        fig = px.bar(x=event_counts.index, y=event_counts.values)
        fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(fig, use_container_width=True)
