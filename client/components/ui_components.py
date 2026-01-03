import streamlit as st

def apply_custom_css():
    """Apply custom CSS styling"""
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

def render_header():
    """Render main header with refresh controls"""
    col1, col2, col3 = st.columns([4, 1, 1])
    
    with col1:
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
    
    with col2:
        auto_refresh = st.checkbox("🔄 Auto-refresh", value=True)
    
    with col3:
        if st.button("↻ Refresh", type="primary"):
            st.cache_data.clear()
            st.rerun()
    
    return auto_refresh

def render_sidebar():
    """Render sidebar navigation"""
    st.sidebar.title("🛡️ Navigation")
    
    # Initialize session state for page selection
    if "selected_page" not in st.session_state:
        st.session_state.selected_page = "🏠 Dashboard Overview"
    
    pages = [
        "🏠 Dashboard Overview",
        "🤖 AI Security Chat",
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
    
    return st.session_state.selected_page
