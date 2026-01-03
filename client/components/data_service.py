import requests
import json
import asyncio
from core.postgres_db import db
import pandas as pd
import streamlit as st

@st.cache_data(ttl=10)  # Shorter cache time
def get_dashboard_data():
    """Fetch real-time dashboard data"""
    try:
        # Make raw data request directly
        response = requests.post(
            "http://localhost:8000/query",
            json={"message": "get raw dashboard data"},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            response_text = data["response"]
            
            # Parse the JSON response
            try:
                parsed = json.loads(response_text)
                if "dashboard_data" in parsed:
                    return parsed["dashboard_data"]
            except json.JSONDecodeError:
                pass
                
        return None
    except:
        return None

@st.cache_data(ttl=10)  # Shorter cache time
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
    """Execute security command via API with intelligent routing"""
    try:
        response = requests.post(
            "http://localhost:8000/query",
            json={"message": command},
            timeout=15
        )
        if response.status_code == 200:
            data = response.json()
            response_text = data["response"]
            
            # Try to parse as JSON for structured data
            try:
                parsed = json.loads(response_text)
                return {"success": True, "data": parsed, "raw_response": response_text}
            except json.JSONDecodeError:
                # Return intelligent text response
                return {"success": True, "message": response_text, "raw_response": response_text}
        return {"success": False, "error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
