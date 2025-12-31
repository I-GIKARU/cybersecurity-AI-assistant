import streamlit as st
import time
from components.ui_components import apply_custom_css, render_header, render_sidebar
from components.data_service import get_dashboard_data, get_security_events
from components.dashboard_pages import show_dashboard_overview, show_live_threat_monitor, show_security_analytics
from components.additional_pages import show_threat_intelligence, show_incident_response, show_security_reports, show_system_health

# Page config
st.set_page_config(
    page_title="🔒 Cybersecurity Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

def main():
    # Apply styling
    apply_custom_css()
    
    # Render header
    render_header()
    
    # Render sidebar and get navigation
    auto_refresh, page = render_sidebar()
    
    # Get real-time data
    dashboard_data = get_dashboard_data()
    events_df = get_security_events()
    
    # Route to appropriate page
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

if __name__ == "__main__":
    main()
