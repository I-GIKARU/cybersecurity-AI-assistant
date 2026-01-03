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
        threat_level = dashboard_data.get("threat_level", "UNKNOWN").upper()
        color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(threat_level, "⚪")
        st.metric("🎯 Threat Level", f"{color} {threat_level}")
    
    with col2:
        total_events = dashboard_data.get("total_events", 0)
        st.metric("📊 Events (24h)", total_events, delta=f"+{total_events - 10}" if total_events > 10 else None)
    
    with col3:
        # Calculate system health from metrics
        metrics = dashboard_data.get("system_metrics", {})
        cpu = metrics.get("cpu_percent", 0)
        memory = metrics.get("memory_percent", 0)
        
        if cpu > 80 or memory > 90:
            system_health = "CRITICAL"
            health_color = "🔴"
        elif cpu > 60 or memory > 75:
            system_health = "WARNING" 
            health_color = "🟡"
        else:
            system_health = "HEALTHY"
            health_color = "🟢"
            
        st.metric("💻 System Health", f"{health_color} {system_health}")
    
    with col4:
        response_time = dashboard_data.get("response_metrics", {}).get("avg_response_time", 0)
        st.metric("⚡ Avg Response", f"{response_time}s", delta=f"-{2.5 - response_time:.1f}s" if response_time < 2.5 else None)
    
    # Severity breakdown from real data
    st.subheader("🚨 Security Events Summary")
    severity_breakdown = dashboard_data.get("severity_breakdown", {})
    
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("🔴 Critical", severity_breakdown.get("critical", 0))
    with col2:
        st.metric("🟠 High", severity_breakdown.get("high", 0))
    with col3:
        st.metric("🟡 Medium", severity_breakdown.get("medium", 0))
    with col4:
        st.metric("🟢 Low", severity_breakdown.get("low", 0))
    with col5:
        st.metric("🔵 Info", severity_breakdown.get("info", 0))
    
    # Event types breakdown
    st.subheader("🔍 Event Types Distribution")
    event_types = dashboard_data.get("event_types", {})
    if event_types:
        col1, col2 = st.columns(2)
        
        with col1:
            # Show top event types
            sorted_events = sorted(event_types.items(), key=lambda x: x[1], reverse=True)
            for event_type, count in sorted_events[:5]:
                st.write(f"• **{event_type.replace('_', ' ').title()}**: {count}")
        
        with col2:
            # Pie chart of event types
            fig = px.pie(values=list(event_types.values()), names=list(event_types.keys()),
                        title="Event Types Breakdown")
            fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig, use_container_width=True)
    
    # System metrics details
    st.subheader("💻 System Metrics")
    if metrics:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("🖥️ CPU Usage", f"{metrics.get('cpu_percent', 0):.1f}%")
            st.metric("💾 Memory Usage", f"{metrics.get('memory_percent', 0):.1f}%")
            st.metric("💽 Disk Usage", f"{metrics.get('disk_usage', 0):.1f}%")
        
        with col2:
            st.metric("🌐 Network Connections", metrics.get("network_connections", 0))
            st.metric("⚙️ Active Processes", metrics.get("active_processes", 0))
            st.metric("👥 Logged Users", metrics.get("logged_users", 0))
        
        with col3:
            st.metric("🔒 Root Processes", metrics.get("root_processes", 0))
            st.metric("❌ Failed Logins", metrics.get("failed_logins", 0))
            st.metric("⚠️ Suspicious Ports", metrics.get("suspicious_ports", 0))
        
        # System uptime and load
        col1, col2 = st.columns(2)
        with col1:
            st.info(f"⏱️ **System Uptime**: {metrics.get('uptime', 'Unknown')}")
        
        with col2:
            load_avg = metrics.get("load_average", {})
            if load_avg:
                st.info(f"📊 **Load Average**: 1m: {load_avg.get('1min', 0):.2f}, 5m: {load_avg.get('5min', 0):.2f}, 15m: {load_avg.get('15min', 0):.2f}")
    
    # Recent events from API data
    recent_events = dashboard_data.get("recent_events", [])
    if recent_events:
        st.subheader("🔍 Recent Security Events")
        
        for event in recent_events[:5]:
            severity = event.get("severity", "unknown")
            severity_color = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}.get(severity, "⚪")
            
            timestamp = event.get("timestamp", "Unknown")[:19] if event.get("timestamp") else "Unknown"
            event_type = event.get("event_type", "Unknown")
            description = event.get("description", "No description")
            status = event.get("status", "Unknown")
            
            st.markdown(f"""
            <div style="border-left: 4px solid {'red' if severity == 'critical' else 'orange' if severity == 'high' else 'yellow' if severity == 'medium' else 'green'}; 
                        padding: 10px; margin: 5px 0; background-color: rgba(255,255,255,0.05);">
                <strong>{severity_color} {timestamp}</strong><br>
                <strong>Type:</strong> {event_type.replace('_', ' ').title()}<br>
                <strong>Status:</strong> {status.title()}<br>
                <strong>Details:</strong> {description}
            </div>
            """, unsafe_allow_html=True)
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Severity Distribution Chart")
        if severity_breakdown:
            fig = px.bar(
                x=list(severity_breakdown.keys()), 
                y=list(severity_breakdown.values()),
                color=list(severity_breakdown.keys()),
                color_discrete_map={
                    "critical": "#ff0000", "high": "#ff6600", "medium": "#ffff00", 
                    "low": "#00ff00", "info": "#0066ff"
                }
            )
            fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("🎯 Threat Level Timeline")
        # Show threat level over time (mock data for now)
        timeline_data = pd.DataFrame({
            "Time": ["6h ago", "4h ago", "2h ago", "Now"],
            "Threat Level": [2, 3, 3, 2 if threat_level == "MEDIUM" else 1]
        })
        fig = px.line(timeline_data, x="Time", y="Threat Level", 
                     title="Threat Level Trend")
        fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(fig, use_container_width=True)

def show_live_threat_monitor(dashboard_data, events_df):
    """Comprehensive live threat monitoring page"""
    st.header("🚨 Live Threat Monitor")
    
    # Real-time Status Bar
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🔴 DEFCON 1", use_container_width=True, type="secondary"):
            result = execute_security_command("Activate DEFCON 1 - maximum security alert level")
            if result and result.get("success"):
                st.error("🚨 DEFCON 1 ACTIVATED")
                st.info(result.get("message", "Maximum alert activated"))
    
    with col2:
        if st.button("🟠 DEFCON 2", use_container_width=True):
            result = execute_security_command("Set security alert level to DEFCON 2 - high readiness")
            if result and result.get("success"):
                st.warning("⚠️ DEFCON 2 ACTIVE")
                st.info(result.get("message", "High alert level set"))
    
    with col3:
        if st.button("🟡 DEFCON 3", use_container_width=True):
            result = execute_security_command("Set security alert level to DEFCON 3 - increased watch")
            if result and result.get("success"):
                st.info("📊 DEFCON 3 ACTIVE")
                st.success(result.get("message", "Increased watch level set"))
    
    with col4:
        if st.button("🟢 DEFCON 5", use_container_width=True):
            result = execute_security_command("Set security alert level to DEFCON 5 - normal readiness")
            if result and result.get("success"):
                st.success("✅ DEFCON 5 NORMAL")
                st.info(result.get("message", "Normal readiness level"))
    
    st.divider()
    
    # Live Threat Feed
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🔴 Active Threat Feed")
        
        # Auto-refresh toggle
        auto_refresh = st.checkbox("🔄 Auto-refresh (30s)", value=True)
        
        if st.button("🔄 Refresh Threats Now", type="primary"):
            result = execute_security_command("Get current active threats and security alerts")
            if result and result.get("success"):
                st.success("✅ Threat feed updated!")
                st.info(result.get("message", "Threat data refreshed"))
        
        # Display active threats
        if not events_df.empty:
            st.markdown("**🚨 Recent High-Priority Events:**")
            high_severity = events_df[events_df['severity'].isin(['critical', 'high'])].head(10)
            
            for _, event in high_severity.iterrows():
                severity_color = "🔴" if event['severity'] == 'critical' else "🟠"
                timestamp = str(event['timestamp'])[:19] if 'timestamp' in event else "Unknown"
                event_type = event.get('event_type', 'Unknown')
                description = event.get('description', 'No description')[:100] + "..."
                
                with st.container():
                    st.markdown(f"""
                    <div style="border-left: 4px solid {'red' if event['severity'] == 'critical' else 'orange'}; 
                                padding: 10px; margin: 5px 0; background-color: rgba(255,255,255,0.05);">
                        <strong>{severity_color} {timestamp}</strong><br>
                        <strong>Type:</strong> {event_type}<br>
                        <strong>Details:</strong> {description}
                    </div>
                    """, unsafe_allow_html=True)
        else:
            st.success("✅ No active high-priority threats detected")
            
            # Show system status instead
            if st.button("📊 Get Current Security Status"):
                result = execute_security_command("Show me current security status and any potential threats")
                if result and result.get("success"):
                    st.info("🛡️ Security Status Update")
                    st.success(result.get("message", "Security status retrieved"))
    
    with col2:
        st.subheader("⚡ Emergency Actions")
        
        st.markdown("**🚨 Critical Response**")
        if st.button("🔒 Emergency Lockdown", use_container_width=True, type="secondary"):
            result = execute_security_command("Execute immediate emergency system lockdown")
            if result and result.get("success"):
                st.error("🚨 EMERGENCY LOCKDOWN INITIATED")
                st.info(result.get("message", "Emergency lockdown in progress"))
        
        if st.button("🛡️ Activate All Shields", use_container_width=True, type="secondary"):
            result = execute_security_command("Activate all security defenses and protection systems")
            if result and result.get("success"):
                st.warning("🛡️ ALL SHIELDS ACTIVATED")
                st.info(result.get("message", "Defense systems online"))
        
        st.markdown("**🔍 Immediate Scans**")
        if st.button("🔍 Emergency Scan", use_container_width=True):
            result = execute_security_command("Perform emergency security scan for immediate threats")
            if result and result.get("success"):
                st.success("🔍 Emergency scan initiated!")
                st.info(result.get("message", "Emergency scan running"))
        
        if st.button("🕵️ Threat Hunt", use_container_width=True):
            result = execute_security_command("Initiate active threat hunting for advanced persistent threats")
            if result and result.get("success"):
                st.success("🕵️ Threat hunting started!")
                st.info(result.get("message", "Threat hunting in progress"))
        
        st.markdown("**📞 Alert Systems**")
        if st.button("📢 Broadcast Alert", use_container_width=True):
            result = execute_security_command("Send security alert broadcast to all systems and personnel")
            if result and result.get("success"):
                st.warning("📢 ALERT BROADCAST SENT")
                st.info(result.get("message", "Alert broadcast completed"))
    
    st.divider()
    
    # Threat Intelligence Feed
    st.subheader("🌍 Global Threat Intelligence")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🌐 Global Threats", use_container_width=True):
            result = execute_security_command("Get latest global threat intelligence and security alerts")
            if result and result.get("success"):
                st.success("🌐 Global intel updated!")
                st.info(result.get("message", "Global threat data retrieved"))
    
    with col2:
        if st.button("🎯 Targeted Attacks", use_container_width=True):
            result = execute_security_command("Check for targeted attacks and advanced persistent threats")
            if result and result.get("success"):
                st.success("🎯 Targeted threat check complete!")
                st.info(result.get("message", "Targeted attack analysis finished"))
    
    with col3:
        if st.button("🚨 Zero-Day Alerts", use_container_width=True):
            result = execute_security_command("Monitor for zero-day exploits and unknown threats")
            if result and result.get("success"):
                st.success("🚨 Zero-day monitoring active!")
                st.info(result.get("message", "Zero-day monitoring enabled"))
    
    # Live System Monitoring
    st.divider()
    st.subheader("📊 Live System Monitoring")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🖥️ System Health Check", use_container_width=True):
            result = execute_security_command("Perform real-time system health and security check")
            if result and result.get("success"):
                st.success("🖥️ System health checked!")
                st.info(result.get("message", "System health analysis completed"))
    
    with col2:
        if st.button("🌐 Network Monitor", use_container_width=True):
            result = execute_security_command("Monitor network traffic for suspicious activity")
            if result and result.get("success"):
                st.success("🌐 Network monitoring active!")
                st.info(result.get("message", "Network monitoring enabled"))
    
    # Auto-refresh functionality
    if auto_refresh:
        import time
        time.sleep(30)
        st.rerun()

def show_security_analytics(events_df):
    """Comprehensive security analytics page"""
    st.header("📊 Security Analytics & Intelligence")
    
    # Analytics Controls
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔍 Generate Analytics Report", type="primary", use_container_width=True):
            result = execute_security_command("Generate comprehensive security analytics report with trends and insights")
            if result and result.get("success"):
                st.success("✅ Analytics report generated!")
                st.info(result.get("message", "Analytics completed"))
    
    with col2:
        if st.button("📈 Trend Analysis", use_container_width=True):
            result = execute_security_command("Analyze security trends and patterns over time")
            if result and result.get("success"):
                st.success("✅ Trend analysis complete!")
                st.info(result.get("message", "Trend analysis finished"))
    
    with col3:
        if st.button("🎯 Risk Assessment", use_container_width=True):
            result = execute_security_command("Perform comprehensive risk assessment and vulnerability analysis")
            if result and result.get("success"):
                st.success("✅ Risk assessment done!")
                st.info(result.get("message", "Risk assessment completed"))
    
    st.divider()
    
    # Data Visualization
    if not events_df.empty:
        st.subheader("📈 Security Event Analytics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**📊 Event Timeline**")
            events_df['datetime'] = pd.to_datetime(events_df['timestamp'])
            timeline_data = events_df.groupby([events_df['datetime'].dt.hour, 'severity']).size().reset_index(name='count')
            fig = px.line(timeline_data, x='datetime', y='count', color='severity', 
                         title="Security Events Over Time")
            fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("**⚠️ Event Types Distribution**")
            event_counts = events_df['event_type'].value_counts()
            fig = px.pie(values=event_counts.values, names=event_counts.index, 
                        title="Event Types Breakdown")
            fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig, use_container_width=True)
        
        # Severity Analysis
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**🚨 Severity Distribution**")
            severity_counts = events_df['severity'].value_counts()
            fig = px.bar(x=severity_counts.index, y=severity_counts.values,
                        title="Events by Severity Level",
                        color=severity_counts.index,
                        color_discrete_map={
                            'critical': 'red',
                            'high': 'orange', 
                            'medium': 'yellow',
                            'low': 'green',
                            'info': 'blue'
                        })
            fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("**📅 Daily Event Volume**")
            daily_events = events_df.groupby(events_df['datetime'].dt.date).size().reset_index(name='count')
            fig = px.area(daily_events, x='datetime', y='count', 
                         title="Daily Security Event Volume")
            fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig, use_container_width=True)
    
    else:
        st.info("📊 No security event data available for visualization")
        
        # Show alternative analytics
        st.subheader("🔍 Live Security Analytics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📊 System Performance Analytics", use_container_width=True):
                result = execute_security_command("Analyze system performance metrics and security implications")
                if result and result.get("success"):
                    st.success("✅ Performance analytics complete!")
                    st.info(result.get("message", "Performance analysis finished"))
        
        with col2:
            if st.button("🌐 Network Traffic Analysis", use_container_width=True):
                result = execute_security_command("Analyze network traffic patterns for security anomalies")
                if result and result.get("success"):
                    st.success("✅ Network analysis complete!")
                    st.info(result.get("message", "Network analysis finished"))
    
    st.divider()
    
    # Advanced Analytics
    st.subheader("🧠 AI-Powered Analytics")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**🤖 Machine Learning**")
        
        if st.button("🔍 Anomaly Detection", use_container_width=True):
            result = execute_security_command("Run AI-powered anomaly detection on security data")
            if result and result.get("success"):
                st.success("✅ Anomaly detection complete!")
                st.info(result.get("message", "Anomaly analysis finished"))
        
        if st.button("📊 Predictive Analysis", use_container_width=True):
            result = execute_security_command("Perform predictive security analysis using machine learning")
            if result and result.get("success"):
                st.success("✅ Predictive analysis done!")
                st.info(result.get("message", "Predictive analysis completed"))
    
    with col2:
        st.markdown("**📈 Statistical Analysis**")
        
        if st.button("📊 Correlation Analysis", use_container_width=True):
            result = execute_security_command("Analyze correlations between security events and system metrics")
            if result and result.get("success"):
                st.success("✅ Correlation analysis complete!")
                st.info(result.get("message", "Correlation analysis finished"))
        
        if st.button("📈 Regression Analysis", use_container_width=True):
            result = execute_security_command("Perform regression analysis on security incident patterns")
            if result and result.get("success"):
                st.success("✅ Regression analysis done!")
                st.info(result.get("message", "Regression analysis completed"))
    
    with col3:
        st.markdown("**🎯 Behavioral Analysis**")
        
        if st.button("👤 User Behavior Analytics", use_container_width=True):
            result = execute_security_command("Analyze user behavior patterns for security anomalies")
            if result and result.get("success"):
                st.success("✅ Behavior analysis complete!")
                st.info(result.get("message", "User behavior analysis finished"))
        
        if st.button("🌐 Network Behavior Analysis", use_container_width=True):
            result = execute_security_command("Analyze network behavior patterns and traffic anomalies")
            if result and result.get("success"):
                st.success("✅ Network behavior analysis done!")
                st.info(result.get("message", "Network behavior analysis completed"))
    
    # Custom Analytics Query
    st.divider()
    st.subheader("💬 Custom Analytics Query")
    
    analytics_query = st.text_area("Ask for specific analytics:", 
                                  placeholder="e.g., 'What are the most common attack patterns in the last week?'")
    
    if st.button("🔍 Run Analytics Query", type="primary") and analytics_query:
        with st.spinner("Processing analytics query..."):
            result = execute_security_command(f"Security analytics query: {analytics_query}")
            if result and result.get("success"):
                st.success("✅ Analytics query processed!")
                st.info(result.get("message", "Analytics query completed"))
