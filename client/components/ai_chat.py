import streamlit as st
from components.data_service import execute_security_command

def show_ai_chat():
    """AI-powered cybersecurity chat interface"""
    st.header("🤖 AI Security Assistant")
    
    # Initialize chat history
    if "messages" not in st.session_state:
        st.session_state.messages = [
            {"role": "assistant", "content": "Hello! I'm your AI cybersecurity assistant. Ask me anything about your security posture, system health, or cybersecurity best practices."}
        ]
    
    # Chat container with fixed height
    chat_container = st.container()
    
    with chat_container:
        # Display chat messages
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
    
    # Chat input at bottom
    if prompt := st.chat_input("Ask me about cybersecurity..."):
        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": prompt})
        
        # Display user message
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # Get AI response
        with st.chat_message("assistant"):
            with st.spinner("Analyzing..."):
                result = execute_security_command(prompt)
                
                if result and result.get("success"):
                    if "message" in result:
                        response = result["message"]
                    elif "data" in result:
                        response = f"Here's the data you requested:\n\n```json\n{result['data']}\n```"
                    else:
                        response = result.get("raw_response", "Response received")
                else:
                    error_msg = result.get("error", "Connection failed") if result else "Unable to connect to security backend"
                    response = f"❌ **Error**: {error_msg}\n\nPlease check if the security backend is running and try again."
                
                st.markdown(response)
                
                # Add assistant response to chat history
                st.session_state.messages.append({"role": "assistant", "content": response})
    
    # Sidebar with chat controls
    with st.sidebar:
        st.markdown("---")
        st.subheader("💬 Chat Controls")
        
        if st.button("🗑️ Clear Chat", use_container_width=True):
            st.session_state.messages = [
                {"role": "assistant", "content": "Hello! I'm your AI cybersecurity assistant. Ask me anything about your security posture, system health, or cybersecurity best practices."}
            ]
            st.rerun()
        
        if st.button("💾 Export Chat", use_container_width=True):
            chat_export = "\n".join([f"{msg['role'].upper()}: {msg['content']}" for msg in st.session_state.messages])
            st.download_button(
                label="📄 Download Chat Log",
                data=chat_export,
                file_name="security_chat_log.txt",
                mime="text/plain",
                use_container_width=True
            )
        
        st.markdown("---")
        st.subheader("💡 Quick Examples")
        
        examples = [
            "How is my network?",
            "Check my RAM usage",
            "Scan for vulnerabilities", 
            "Show security dashboard",
            "I think I'm being hacked",
            "Password best practices"
        ]
        
        for example in examples:
            if st.button(f"💬 {example}", use_container_width=True, key=f"example_{example}"):
                # Add example to chat
                st.session_state.messages.append({"role": "user", "content": example})
                
                # Get response
                result = execute_security_command(example)
                if result and result.get("success"):
                    response = result.get("message", result.get("raw_response", "Response received"))
                else:
                    response = "❌ Unable to process request"
                
                st.session_state.messages.append({"role": "assistant", "content": response})
                st.rerun()

def show_quick_actions():
    """Quick action buttons for common security tasks"""
    st.header("⚡ Quick Security Actions")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.subheader("🔍 System Checks")
        if st.button("💾 Check RAM", use_container_width=True):
            result = execute_security_command("check my RAM usage")
            if result and result.get("success"):
                st.success("✅ RAM Check Complete")
                st.info(result.get("message", "Check completed"))
        
        if st.button("🌐 Check Network", use_container_width=True):
            result = execute_security_command("how is my network?")
            if result and result.get("success"):
                st.success("✅ Network Check Complete")
                st.info(result.get("message", "Check completed"))
    
    with col2:
        st.subheader("🛡️ Security Scans")
        if st.button("🔍 Vulnerability Scan", use_container_width=True):
            result = execute_security_command("scan my system for vulnerabilities")
            if result and result.get("success"):
                st.success("✅ Scan Complete")
                st.info(result.get("message", "Scan completed"))
        
        if st.button("📊 Security Dashboard", use_container_width=True):
            result = execute_security_command("show me the security dashboard")
            if result and result.get("success"):
                st.success("✅ Dashboard Retrieved")
                st.info(result.get("message", "Dashboard data retrieved"))
    
    with col3:
        st.subheader("🚨 Emergency Response")
        if st.button("🔒 Emergency Lockdown", use_container_width=True, type="secondary"):
            result = execute_security_command("execute emergency system lockdown")
            if result and result.get("success"):
                st.warning("⚠️ Emergency Response Initiated")
                st.info(result.get("message", "Response initiated"))
        
        if st.button("📋 Incident Report", use_container_width=True):
            result = execute_security_command("generate security incident report")
            if result and result.get("success"):
                st.success("✅ Report Generated")
                st.info(result.get("message", "Report generated"))
        
        if st.button("📄 Generate PDF Report", use_container_width=True):
            with st.spinner("Generating PDF report..."):
                result = execute_security_command("generate comprehensive security report")
                if result and result.get("success"):
                    response = result.get("message", result.get("raw_response", ""))
                    st.success("✅ PDF Report Generated!")
                    
                    # Extract PDF path from response
                    import re
                    import time
                    path_match = re.search(r'path: (.+?)(?:\n|$)', response)
                    if path_match:
                        pdf_path = path_match.group(1).strip()
                        
                        # Provide download button
                        try:
                            import requests
                            download_response = requests.get(f"http://localhost:8000/download-report?path={pdf_path}")
                            if download_response.status_code == 200:
                                st.download_button(
                                    label="📥 Download PDF Report",
                                    data=download_response.content,
                                    file_name=f"security_report_{int(time.time())}.pdf",
                                    mime="application/pdf",
                                    type="primary",
                                    use_container_width=True
                                )
                            else:
                                st.error("❌ Failed to fetch PDF")
                        except Exception as e:
                            st.error(f"❌ Download error: {str(e)}")
                    else:
                        st.info(response)
                else:
                    st.error("❌ Failed to generate report")
