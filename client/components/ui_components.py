import streamlit as st

def apply_custom_css():
    """Apply custom CSS styling"""
    st.markdown("""
    <style>
        .sidebar-title {
            color: #00ff00;
            font-size: 18px;
            font-weight: bold;
            text-align: center;
            background: #1a1a1a;
            padding: 10px;
            border-radius: 5px;
            border: 2px solid #00ff00;
            margin: -1rem -1rem 1rem -1rem;
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

def render_navbar():
    """Render empty navbar"""
    return True

def render_sidebar():
    """Render sidebar with styled title, navigation and refresh controls"""
    # Styled title at the very top
    st.sidebar.markdown("""
    <div class="sidebar-title">
        🔒 CYBERSECURITY<br>COMMAND CENTER
    </div>
    """, unsafe_allow_html=True)
    
    # Refresh controls
    col1, col2 = st.sidebar.columns(2)
    with col1:
        auto_refresh = st.checkbox("🔄", value=True, help="Auto-refresh")
    with col2:
        if st.button("↻", help="Refresh Now", type="primary", use_container_width=True):
            # Clear all cached data
            from .data_service import get_dashboard_data, get_security_events
            get_dashboard_data.clear()
            get_security_events.clear()
            st.rerun()
    
    # AI Chat right below refresh
    if st.sidebar.button("🤖 AI Security Chat", use_container_width=True, 
                       type="primary" if st.session_state.get("selected_page") == "🤖 AI Security Chat" else "secondary"):
        st.session_state.selected_page = "🤖 AI Security Chat"
        st.rerun()
    
    # Initialize session state for page selection
    if "selected_page" not in st.session_state:
        st.session_state.selected_page = "🏠 Dashboard Overview"
    
    pages = [
        "🏠 Dashboard Overview",
        "⚡ Quick Actions", 
        "🚨 Live Threat Monitor", 
        "📊 Security Analytics",
        "🔍 Threat Intelligence",
        "⚡ Incident Response",
        "📋 Security Reports",
        "🛠️ System Health"
    ]
    
    # Create clickable list of pages
    for page in pages:
        if st.sidebar.button(page, use_container_width=True, 
                           type="primary" if st.session_state.selected_page == page else "secondary"):
            st.session_state.selected_page = page
            st.rerun()
    
    return auto_refresh, st.session_state.selected_page
