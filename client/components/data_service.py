import requests
import json
import sqlite3
import pandas as pd
import streamlit as st

@st.cache_data(ttl=30)
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

def execute_security_command(command):
    """Execute security command via API"""
    try:
        response = requests.post(
            "http://localhost:8000/query",
            json={"message": command},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None
