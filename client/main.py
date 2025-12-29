import streamlit as st
from services.api_client import CybersecurityAgentAPI

st.set_page_config(
    page_title="Cybersecurity AI Agent",
    page_icon="🛡️",
    layout="wide"
)

@st.cache_resource
def get_api_client():
    return CybersecurityAgentAPI("http://localhost:8000")

api = get_api_client()

st.title("🛡️ Cybersecurity AI Agent")
st.markdown("AI Threat Detection & Security Agent")

# Sidebar for features
st.sidebar.title("Security Services")
feature = st.sidebar.selectbox(
    "Choose a service:",
    ["💬 Security Chat", "🔍 Threat Detection", "📊 Vulnerability Scan", "🚨 Incident Response", "📋 Security Audit"]
)

if feature == "💬 Security Chat":
    st.header("Cybersecurity Assistant")
    
    if "messages" not in st.session_state:
        st.session_state.messages = []
    
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    
    if prompt := st.chat_input("Ask about cybersecurity..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        
        with st.chat_message("assistant"):
            with st.spinner("Analyzing security..."):
                response = api.query(prompt)
                if response:
                    st.markdown(response["response"])
                    st.session_state.messages.append({"role": "assistant", "content": response["response"]})
                    st.caption(f"Confidence: {response['confidence']:.0%}")

elif feature == "🔍 Threat Detection":
    st.header("AI Threat Analysis")
    
    col1, col2 = st.columns(2)
    with col1:
        log_data = st.text_area("System Logs", height=200)
        network_data = st.text_area("Network Traffic Data")
    with col2:
        threat_type = st.selectbox("Threat Type", ["Malware", "Phishing", "DDoS", "Intrusion", "All"])
        
    if st.button("Analyze Threats"):
        if log_data:
            with st.spinner("Scanning for threats..."):
                response = api.detect_threats(log_data, network_data, threat_type)
                if response:
                    st.markdown(response["response"])

elif feature == "📊 Vulnerability Scan":
    st.header("Security Vulnerability Assessment")
    
    col1, col2 = st.columns(2)
    with col1:
        target_system = st.text_input("Target System/IP")
        scan_type = st.selectbox("Scan Type", ["Port Scan", "Web App", "Network", "Full"])
    with col2:
        scan_depth = st.selectbox("Scan Depth", ["Quick", "Standard", "Deep"])
        
    if st.button("Start Vulnerability Scan"):
        if target_system:
            response = api.vulnerability_scan(target_system, scan_type, scan_depth)
            if response:
                st.markdown(response["response"])

elif feature == "🚨 Incident Response":
    st.header("Security Incident Management")
    
    incident_type = st.selectbox("Incident Type", 
        ["Data Breach", "Malware Infection", "Unauthorized Access", "DDoS Attack", "Phishing"])
    incident_details = st.text_area("Incident Details")
    
    if st.button("Generate Response Plan"):
        if incident_details:
            response = api.incident_response(incident_type, incident_details)
            if response:
                st.markdown(response["response"])

elif feature == "📋 Security Audit":
    st.header("Security Compliance Audit")
    
    audit_framework = st.selectbox("Framework", ["ISO 27001", "NIST", "SOC 2", "GDPR", "HIPAA"])
    system_info = st.text_area("System Information")
    
    if st.button("Run Security Audit"):
        response = api.security_audit(audit_framework, system_info)
        if response:
            st.markdown(response["response"])
