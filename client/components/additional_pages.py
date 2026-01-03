import streamlit as st
import plotly.graph_objects as go
import json
from components.data_service import execute_security_command

def show_threat_intelligence():
    """Comprehensive threat intelligence page"""
    st.header("🔍 Threat Intelligence Center")
    
    # Threat Level Overview
    st.subheader("🌡️ Current Threat Level")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🔴 Critical Threats", use_container_width=True):
            result = execute_security_command("show me current critical security threats and indicators")
            if result and result.get("success"):
                st.error("🔴 Critical Threats Analysis")
                st.info(result.get("message", "Critical threat analysis completed"))
    
    with col2:
        if st.button("🟠 High Priority", use_container_width=True):
            result = execute_security_command("analyze high priority security threats in our environment")
            if result and result.get("success"):
                st.warning("🟠 High Priority Threats")
                st.info(result.get("message", "High priority analysis completed"))
    
    with col3:
        if st.button("🟡 Medium Risk", use_container_width=True):
            result = execute_security_command("review medium risk security threats and vulnerabilities")
            if result and result.get("success"):
                st.info("🟡 Medium Risk Assessment")
                st.success(result.get("message", "Medium risk analysis completed"))
    
    with col4:
        if st.button("🟢 Low Risk", use_container_width=True):
            result = execute_security_command("check low risk security indicators and baseline threats")
            if result and result.get("success"):
                st.success("🟢 Low Risk Status")
                st.info(result.get("message", "Low risk analysis completed"))
    
    st.divider()
    
    # IOC Analysis
    st.subheader("🎯 Indicator of Compromise (IOC) Analysis")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        ioc_type = st.selectbox("IOC Type:", ["IP Address", "Domain", "File Hash (MD5/SHA1/SHA256)", "Email", "URL"])
        ioc_input = st.text_input("Enter IOC:", placeholder="Enter the indicator to analyze...")
        
        if st.button("🔍 Analyze IOC", type="primary") and ioc_input:
            with st.spinner("Analyzing indicator..."):
                result = execute_security_command(f"Perform comprehensive threat intelligence analysis on this {ioc_type.lower()}: {ioc_input}")
                if result and result.get("success"):
                    st.success(f"✅ Analysis complete for {ioc_input}")
                    st.info(result.get("message", "IOC analysis completed"))
                    
                    # Show analysis results
                    st.subheader("📊 Analysis Results")
                    st.code(f"IOC: {ioc_input}\nType: {ioc_type}\nStatus: Analyzed")
    
    with col2:
        st.markdown("**🔍 IOC Examples:**")
        st.code("192.168.1.100")
        st.code("malicious.com")
        st.code("a1b2c3d4e5f6...")
        st.code("phish@evil.com")
        st.code("http://bad.site")
    
    st.divider()
    
    # Threat Hunting
    st.subheader("🕵️ Advanced Threat Hunting")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**🔍 Proactive Hunting**")
        
        if st.button("🕵️ Hunt for APT Activity", use_container_width=True):
            result = execute_security_command("Hunt for advanced persistent threat indicators and suspicious patterns")
            if result and result.get("success"):
                st.success("✅ APT hunting initiated!")
                st.info(result.get("message", "APT analysis in progress"))
        
        if st.button("🔍 Zero-Day Detection", use_container_width=True):
            result = execute_security_command("Scan for zero-day exploits and unknown threat patterns")
            if result and result.get("success"):
                st.success("✅ Zero-day detection started!")
                st.info(result.get("message", "Zero-day scanning in progress"))
        
        if st.button("🌐 Network Anomalies", use_container_width=True):
            result = execute_security_command("Detect network anomalies and suspicious traffic patterns")
            if result and result.get("success"):
                st.success("✅ Network analysis initiated!")
                st.info(result.get("message", "Network anomaly detection running"))
    
    with col2:
        st.markdown("**📊 Intelligence Feeds**")
        
        if st.button("🌍 Global Threat Feed", use_container_width=True):
            result = execute_security_command("Get latest global threat intelligence and security indicators")
            if result and result.get("success"):
                st.success("✅ Global feed updated!")
                st.info(result.get("message", "Threat feed analysis completed"))
        
        if st.button("🏢 Industry Threats", use_container_width=True):
            result = execute_security_command("Analyze industry-specific threats and attack patterns")
            if result and result.get("success"):
                st.success("✅ Industry analysis complete!")
                st.info(result.get("message", "Industry threat analysis finished"))
        
        if st.button("🎯 Targeted Attacks", use_container_width=True):
            result = execute_security_command("Identify targeted attacks and spear phishing campaigns")
            if result and result.get("success"):
                st.success("✅ Targeted attack analysis done!")
                st.info(result.get("message", "Targeted attack detection completed"))
    
    st.divider()
    
    # Threat Intelligence Reports
    st.subheader("📋 Intelligence Reports")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📊 Daily Intel Brief", use_container_width=True):
            result = execute_security_command("Generate daily threat intelligence briefing with current threats")
            if result and result.get("success"):
                st.success("✅ Daily brief generated!")
                st.info(result.get("message", "Intelligence briefing completed"))
    
    with col2:
        if st.button("📈 Threat Trends", use_container_width=True):
            result = execute_security_command("Analyze threat trends and emerging attack patterns")
            if result and result.get("success"):
                st.success("✅ Trend analysis complete!")
                st.info(result.get("message", "Threat trend analysis finished"))
    
    with col3:
        if st.button("🎯 Attribution Analysis", use_container_width=True):
            result = execute_security_command("Perform threat actor attribution and campaign analysis")
            if result and result.get("success"):
                st.success("✅ Attribution analysis done!")
                st.info(result.get("message", "Threat attribution completed"))
    
    # Custom Threat Query
    st.divider()
    st.subheader("💬 Custom Threat Intelligence Query")
    
    custom_query = st.text_area("Ask about specific threats:", 
                               placeholder="e.g., 'What are the latest ransomware families targeting our industry?'")
    
    if st.button("🔍 Submit Query", type="primary") and custom_query:
        with st.spinner("Processing threat intelligence query..."):
            result = execute_security_command(f"Threat intelligence query: {custom_query}")
            if result and result.get("success"):
                st.success("✅ Query processed!")
                st.info(result.get("message", "Threat intelligence analysis completed"))

def show_incident_response():
    """Comprehensive incident response page"""
    st.header("⚡ Incident Response Center")
    
    # Emergency Actions
    st.subheader("🚨 Emergency Response")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔒 Emergency Lockdown", type="secondary", use_container_width=True):
            result = execute_security_command("Execute emergency system lockdown due to critical security threat")
            if result and result.get("success"):
                st.error("🚨 EMERGENCY LOCKDOWN INITIATED")
                st.info(result.get("message", "System lockdown in progress"))
    
    with col2:
        if st.button("🛡️ Activate All Defenses", type="secondary", use_container_width=True):
            result = execute_security_command("Activate all security defenses and monitoring systems")
            if result and result.get("success"):
                st.warning("🛡️ ALL DEFENSES ACTIVATED")
                st.info(result.get("message", "Defense systems online"))
    
    with col3:
        if st.button("📞 Alert Security Team", type="secondary", use_container_width=True):
            result = execute_security_command("Send emergency alert to security team about critical incident")
            if result and result.get("success"):
                st.success("📞 SECURITY TEAM ALERTED")
                st.info(result.get("message", "Alert sent successfully"))
    
    st.divider()
    
    # Incident Reporting
    st.subheader("📝 Report Security Incident")
    
    with st.form("incident_form"):
        incident_type = st.selectbox("Incident Type:", [
            "Malware Detection",
            "Phishing Attack", 
            "Data Breach",
            "Unauthorized Access",
            "Network Intrusion",
            "Ransomware",
            "Suspicious Activity",
            "Other"
        ])
        
        severity = st.selectbox("Severity Level:", ["Low", "Medium", "High", "Critical"])
        
        description = st.text_area("Incident Description:", 
                                 placeholder="Describe what happened, when it occurred, and any symptoms you've noticed...")
        
        affected_systems = st.text_input("Affected Systems:", 
                                       placeholder="List affected computers, servers, or networks")
        
        submitted = st.form_submit_button("🚨 Submit Incident Report", type="primary")
        
        if submitted and description:
            # Create detailed incident report
            incident_report = f"""
            SECURITY INCIDENT REPORT:
            Type: {incident_type}
            Severity: {severity}
            Description: {description}
            Affected Systems: {affected_systems}
            
            Please analyze this incident and initiate appropriate response measures.
            """
            
            result = execute_security_command(incident_report)
            if result and result.get("success"):
                st.success("✅ Incident reported and analysis initiated!")
                st.info(result.get("message", "Incident processing started"))
                
                # Show recommended actions based on response
                if "critical" in result.get("message", "").lower():
                    st.error("🚨 CRITICAL INCIDENT - Immediate action required!")
                elif "high" in result.get("message", "").lower():
                    st.warning("⚠️ HIGH PRIORITY - Urgent response needed")
            else:
                st.error("❌ Failed to submit incident report")
    
    st.divider()
    
    # Response Tools
    st.subheader("🛠️ Incident Response Tools")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**🔒 Containment Actions**")
        
        if st.button("🔒 Quarantine Suspicious File", use_container_width=True):
            file_path = st.text_input("File path to quarantine:", key="quarantine_file")
            if file_path:
                result = execute_security_command(f"Quarantine this suspicious file immediately: {file_path}")
                if result and result.get("success"):
                    st.success("✅ File quarantine initiated!")
                    st.info(result.get("message", "Quarantine in progress"))
        
        if st.button("🚫 Block Malicious IP", use_container_width=True):
            ip_address = st.text_input("IP address to block:", key="block_ip")
            if ip_address:
                result = execute_security_command(f"Block this malicious IP address immediately: {ip_address}")
                if result and result.get("success"):
                    st.success("✅ IP blocking initiated!")
                    st.info(result.get("message", "IP block in progress"))
        
        if st.button("🌐 Isolate Network Segment", use_container_width=True):
            result = execute_security_command("Isolate compromised network segment to prevent lateral movement")
            if result and result.get("success"):
                st.warning("⚠️ Network isolation initiated!")
                st.info(result.get("message", "Network isolation in progress"))
    
    with col2:
        st.markdown("**🔍 Investigation Tools**")
        
        if st.button("📊 Generate Forensic Report", use_container_width=True):
            result = execute_security_command("Generate detailed forensic analysis report for current incident")
            if result and result.get("success"):
                st.success("✅ Forensic analysis initiated!")
                st.info(result.get("message", "Forensic report generation started"))
        
        if st.button("🔍 Deep System Scan", use_container_width=True):
            result = execute_security_command("Perform comprehensive deep scan of all systems for threats")
            if result and result.get("success"):
                st.success("✅ Deep scan initiated!")
                st.info(result.get("message", "System scan in progress"))
        
        if st.button("📋 Collect Evidence", use_container_width=True):
            result = execute_security_command("Collect and preserve digital evidence for incident investigation")
            if result and result.get("success"):
                st.success("✅ Evidence collection started!")
                st.info(result.get("message", "Evidence preservation in progress"))
    
    st.divider()
    
    # Recovery Actions
    st.subheader("🔄 Recovery & Restoration")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔄 Restore from Backup", use_container_width=True):
            result = execute_security_command("Initiate system restoration from clean backup")
            if result and result.get("success"):
                st.success("✅ Backup restoration initiated!")
                st.info(result.get("message", "Restoration in progress"))
    
    with col2:
        if st.button("🔧 Reset Security Settings", use_container_width=True):
            result = execute_security_command("Reset all security settings to secure defaults")
            if result and result.get("success"):
                st.success("✅ Security reset initiated!")
                st.info(result.get("message", "Security reset in progress"))
    
    with col3:
        if st.button("✅ Verify System Integrity", use_container_width=True):
            result = execute_security_command("Verify system integrity and confirm threat elimination")
            if result and result.get("success"):
                st.success("✅ Integrity verification started!")
                st.info(result.get("message", "System verification in progress"))

def show_security_reports():
    """Security reports page with PDF generation"""
    st.header("📋 Security Reports")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Generate Report")
        report_type = st.selectbox("Report Type:", ["Comprehensive", "Executive Summary", "Technical Analysis", "Compliance Report"])
        time_range = st.selectbox("Time Range:", ["Last 24 Hours", "Last Week", "Last Month"])
        
        if st.button("📋 Generate PDF Report", type="primary"):
            with st.spinner("Generating PDF report..."):
                # Create specific command for PDF report generation
                command = f"generate {report_type.lower()} security report for {time_range.lower()}"
                result = execute_security_command(command)
                
                if result and result.get("success"):
                    response = result.get("message", result.get("raw_response", ""))
                    st.success("✅ Report generated successfully!")
                    st.info(response)
                    
                    # Extract PDF path from response
                    import re
                    import time
                    path_match = re.search(r'path: (.+?)(?:\n|$)', response)
                    if path_match:
                        pdf_path = path_match.group(1).strip()
                        
                        # Try to read the PDF file and provide download
                        try:
                            import requests
                            download_response = requests.get(f"http://localhost:8000/download-report?path={pdf_path}")
                            if download_response.status_code == 200:
                                st.download_button(
                                    label="📥 Download PDF Report",
                                    data=download_response.content,
                                    file_name=f"security_report_{int(time.time())}.pdf",
                                    mime="application/pdf",
                                    type="primary"
                                )
                            else:
                                st.error("❌ Failed to download PDF file")
                        except Exception as e:
                            st.error(f"❌ Download error: {str(e)}")
                            # Fallback: show download link
                            download_url = f"http://localhost:8000/download-report?path={pdf_path}"
                            st.markdown(f"[📥 Download PDF Report]({download_url})")
                else:
                    error_msg = result.get("error", "Unknown error") if result else "Connection failed"
                    st.error(f"❌ Error generating report: {error_msg}")
    
    with col2:
        st.subheader("📈 Report Templates")
        
        st.markdown("**📊 Comprehensive Report**")
        st.write("• Executive summary")
        st.write("• Detailed security events")
        st.write("• System health metrics")
        st.write("• Security recommendations")
        
        st.markdown("**👔 Executive Summary**")
        st.write("• High-level security overview")
        st.write("• Key risk indicators")
        st.write("• Business impact analysis")
        
        st.markdown("---")
        st.subheader("📧 Email Reports")
        
        email_recipient = st.text_input("📧 Email Address:", placeholder="admin@company.com")
        
        if st.button("📧 Generate & Email Report", type="secondary"):
            if email_recipient:
                with st.spinner("Generating and sending report..."):
                    command = f"generate security report and email it to {email_recipient}"
                    result = execute_security_command(command)
                    
                    if result and result.get("success"):
                        response = result.get("message", result.get("raw_response", ""))
                        if "email" in response.lower() and "sent" in response.lower():
                            st.success(f"✅ Report emailed to {email_recipient}")
                        else:
                            st.success("✅ Report generated")
                        st.info(response)
                    else:
                        st.error("❌ Failed to send email report")
            else:
                st.warning("⚠️ Please enter an email address")
        
        st.markdown("**🔧 Technical Analysis**")
        st.write("• Detailed incident analysis")
        st.write("• System performance metrics")
        st.write("• Technical recommendations")
        
        st.markdown("**📋 Compliance Report**")
        st.write("• Regulatory compliance status")
        st.write("• Audit trail information")
        st.write("• Policy adherence metrics")
    
    # Quick actions
    st.subheader("⚡ Quick Actions")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📊 Daily Summary", use_container_width=True):
            result = execute_security_command("generate a daily security summary report")
            if result and result.get("success"):
                st.success("✅ Daily summary generated!")
                st.info(result.get("message", "Summary completed"))
    
    with col2:
        if st.button("🚨 Incident Report", use_container_width=True):
            result = execute_security_command("generate an incident response report for recent security events")
            if result and result.get("success"):
                st.success("✅ Incident report generated!")
                st.info(result.get("message", "Report completed"))
    
    with col3:
        if st.button("📈 Trend Analysis", use_container_width=True):
            result = execute_security_command("generate a security trend analysis report")
            if result and result.get("success"):
                st.success("✅ Trend analysis generated!")
                st.info(result.get("message", "Analysis completed"))
    
    with col2:
        st.subheader("📈 Report History")
        st.info("Previous reports listed here")

def show_system_health(dashboard_data):
    """System health page with real-time data"""
    st.header("🛠️ System Health")
    
    # Get real-time system data
    with st.spinner("Fetching real-time system data..."):
        system_result = execute_security_command("check system info")
        network_result = execute_security_command("how is my network?")
    
    # Parse system data from intelligent response
    system_status = {}
    if system_result and system_result.get("success"):
        # Try to extract data from the response
        response = system_result.get("message", "")
        if "Memory" in response and "CPU" in response:
            # Extract values using simple parsing
            import re
            memory_match = re.search(r'Memory.*?(\d+\.?\d*)%', response)
            cpu_match = re.search(r'CPU.*?(\d+\.?\d*)%', response)
            load_1min_match = re.search(r'1min:\s*(\d+\.?\d*)', response)
            load_5min_match = re.search(r'5min:\s*(\d+\.?\d*)', response)
            load_15min_match = re.search(r'15min:\s*(\d+\.?\d*)', response)
            sent_match = re.search(r'Sent:\s*(\d+\.?\d*)MB', response)
            recv_match = re.search(r'Received:\s*(\d+\.?\d*)MB', response)
            
            if memory_match:
                system_status["memory_percent"] = float(memory_match.group(1))
            if cpu_match:
                system_status["cpu_percent"] = float(cpu_match.group(1))
            if load_1min_match:
                system_status["load_average"] = {"1min": float(load_1min_match.group(1))}
            if sent_match and recv_match:
                system_status["network_io"] = {
                    "bytes_sent": float(sent_match.group(1)) * 1024 * 1024,
                    "bytes_recv": float(recv_match.group(1)) * 1024 * 1024
                }
    
    # Parse network data
    if network_result and network_result.get("success"):
        network_response = network_result.get("message", "")
        connections_match = re.search(r'(\d+)\s+active connections', network_response)
        external_match = re.search(r'(\d+)\s+external', network_response)
        
        if connections_match:
            system_status["network_connections"] = int(connections_match.group(1))
        if external_match:
            system_status["external_connections"] = int(external_match.group(1))
    
    # Fallback to dashboard data if available
    if dashboard_data and dashboard_data.get("system_metrics"):
        dashboard_metrics = dashboard_data["system_metrics"]
        system_status.update(dashboard_metrics)
    
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
    
    # Display intelligent system status
    if system_result and system_result.get("success"):
        st.subheader("🤖 AI System Analysis")
        st.info(system_result.get("message", "System analysis completed"))
    
    if network_result and network_result.get("success"):
        st.subheader("🌐 Network Status")
        st.info(network_result.get("message", "Network analysis completed"))
    
    # System metrics from dashboard data
    if system_status:
        st.subheader("📊 System Metrics")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Network Connections", system_status.get("network_connections", "N/A"))
            st.metric("External Connections", system_status.get("external_connections", "N/A"))
        
        with col2:
            st.metric("CPU Usage", f"{system_status.get('cpu_percent', 'N/A')}%")
            st.metric("Memory Usage", f"{system_status.get('memory_percent', 'N/A')}%")
        
        with col3:
            load_avg = system_status.get("load_average", {})
            st.metric("Load Average (1m)", f"{load_avg.get('1min', 'N/A')}")
            network_io = system_status.get("network_io", {})
            if network_io:
                sent_mb = network_io.get("bytes_sent", 0) / (1024*1024)
                st.metric("Network Sent", f"{sent_mb:.1f} MB")
            else:
                st.metric("Network Sent", "N/A")
        
        with col4:
            if network_io:
                recv_mb = network_io.get("bytes_recv", 0) / (1024*1024)
                st.metric("Network Received", f"{recv_mb:.1f} MB")
            else:
                st.metric("Network Received", "N/A")
            st.metric("System Status", "✅ Healthy" if system_status.get("cpu_percent", 0) < 80 else "⚠️ High Load")
    
    # Refresh button
    if st.button("🔄 Refresh System Data", type="primary"):
        st.cache_data.clear()
        st.rerun()
