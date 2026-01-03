import requests
import json
import asyncio
from core.postgres_db import db
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
            parsed = json.loads(data["response"])
            # Return the nested dashboard_data directly
            return parsed.get("dashboard_data", {})
        return None
    except:
        return None

@st.cache_data(ttl=60)
def get_security_events():
    """Fetch security events from database"""
    try:
        # Run async function in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        events = loop.run_until_complete(db.get_security_events(limit=100))
        loop.close()
        
        if events:
            df = pd.DataFrame(events)
            return df
        return pd.DataFrame()
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
