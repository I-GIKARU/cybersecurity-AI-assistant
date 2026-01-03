from typing import Dict, Any, List, TypedDict, Annotated
import json
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from .llm_provider import LLMProvider

class WorkflowState(TypedDict):
    messages: Annotated[List[BaseMessage], add_messages]
    user_query: str
    tool_choice: str
    tool_result: str
    final_response: str

class CybersecurityWorkflow:
    def __init__(self, llm: LLMProvider, tools: Dict[str, Any]):
        self.llm = llm
        self.tools = tools
        self.tools["llm_response"] = self._create_llm_tool()
        self.workflow = self._build_workflow()
    
    def _create_llm_tool(self):
        """Create LLM response tool for general questions"""
        class LLMTool:
            def __init__(self, llm):
                self.llm = llm
            
            async def execute(self, parameters):
                query = parameters.get("input", "")
                messages = [
                    {"role": "system", "content": "You are a cybersecurity expert. Provide helpful, accurate security advice."},
                    {"role": "user", "content": query}
                ]
                response = await self.llm.generate(messages)
                return {"result": response.content}
        
        return LLMTool(self.llm)
    
    def _build_workflow(self) -> StateGraph:
        workflow = StateGraph(WorkflowState)
        
        # Add nodes
        workflow.add_node("router", self._route_query)
        workflow.add_node("ai_incident_classifier", self._handle_incident)
        workflow.add_node("server_security", self._handle_monitoring)
        workflow.add_node("threat_detection", self._handle_scanning)
        workflow.add_node("realtime_reporting", self._handle_reporting)
        workflow.add_node("llm_response", self._handle_general)
        
        # Set entry point
        workflow.set_entry_point("router")
        
        # Add conditional edges from router
        workflow.add_conditional_edges(
            "router",
            self._route_decision,
            {
                "incident": "ai_incident_classifier",
                "monitoring": "server_security", 
                "scanning": "threat_detection",
                "reporting": "realtime_reporting",
                "general": "llm_response"
            }
        )
        
        # All tools end the workflow
        for tool in ["ai_incident_classifier", "server_security", "threat_detection", "realtime_reporting", "llm_response"]:
            workflow.add_edge(tool, END)
        
        return workflow.compile()
    
    async def _route_query(self, state: WorkflowState) -> WorkflowState:
        """Intelligent routing using LLM"""
        user_query = state["user_query"]
        
        routing_prompt = f"""
Analyze this cybersecurity query and determine the most appropriate tool:

USER QUERY: "{user_query}"

AVAILABLE TOOLS:
- incident: Active threats, malware detection, breach investigation, suspicious files, attack analysis
- monitoring: System performance, network status, resource usage, uptime, connectivity
- scanning: Vulnerability assessment, port scanning, security testing, penetration testing
- reporting: Generate reports, dashboards, metrics, compliance status, analytics
- general: Security advice, best practices, explanations, educational content

SPECIFIC ROUTING RULES:
- "failed login" or "authentication" → incident (log analysis)
- "system health" or "performance" → monitoring
- "vulnerability" or "scan" → scanning
- "report" or "dashboard" → reporting
- Questions/advice → general

Respond with ONLY the tool name: incident, monitoring, scanning, reporting, or general
"""
        
        messages = [
            {"role": "system", "content": "You are a cybersecurity routing expert. Respond with only the tool name."},
            {"role": "user", "content": routing_prompt}
        ]
        
        response = await self.llm.generate(messages)
        tool_choice = response.content.strip().lower()
        
        state["tool_choice"] = tool_choice
        state["messages"].append(HumanMessage(content=user_query))
        
        return state
    
    def _route_decision(self, state: WorkflowState) -> str:
        """Return the routing decision"""
        return state["tool_choice"]
    
    async def _handle_incident(self, state: WorkflowState) -> WorkflowState:
        """Handle security incidents with intelligent action selection"""
        user_query = state["user_query"].lower()
        
        # Use AI to determine specific incident type and action
        incident_prompt = f"""
Analyze this security incident query and determine the specific action needed:

USER QUERY: "{state["user_query"]}"

AVAILABLE ACTIONS:
- check_failed_logins: For login failures, authentication issues, brute force
- analyze_malware: For suspicious files, malware detection, virus alerts
- investigate_breach: For data breaches, unauthorized access, compromised systems
- analyze_network_intrusion: For network attacks, suspicious connections
- classify_user_report: For user-reported security concerns

Respond with ONLY the action name that best matches the incident type.
"""
        
        messages = [
            {"role": "system", "content": "You are a cybersecurity incident expert. Respond with only the action name."},
            {"role": "user", "content": incident_prompt}
        ]
        
        llm_response = await self.llm.generate(messages)
        action = llm_response.content.strip().lower()
        
        # Route to specific incident analysis based on AI decision
        if "failed_login" in action or "login" in user_query or "authentication" in user_query:
            # Use server_security tool for login analysis
            security_tool = self.tools.get("server_security")
            if security_tool and hasattr(security_tool, 'check_failed_logins'):
                result = await security_tool.check_failed_logins()
                state["tool_result"] = self._format_login_analysis(result, state["user_query"])
            else:
                tool = self.tools.get("ai_incident_classifier")
                if tool:
                    result = await tool.auto_classify_incident({"query": state["user_query"]})
                    state["tool_result"] = result.get("human_response", str(result))
                else:
                    state["tool_result"] = "Login analysis not available"
        else:
            # Default incident classification
            tool = self.tools.get("ai_incident_classifier")
            if tool:
                result = await tool.auto_classify_incident({"query": state["user_query"]})
                state["tool_result"] = result.get("human_response", str(result))
            else:
                state["tool_result"] = "Incident classifier not available"
        
        state["final_response"] = state["tool_result"]
        return state
    
    def _format_login_analysis(self, result: Dict[str, Any], query: str) -> str:
        """Format failed login analysis results"""
        if result.get("error"):
            return f"❌ **Login Analysis Error**: {result['error']}"
        
        total_failed = result.get("total_failed_logins", 0)
        recent_attempts = result.get("recent_attempts", [])
        status = result.get("status", "unknown")
        
        if total_failed == 0:
            return "✅ **Login Security**: No failed login attempts detected. System appears secure."
        elif total_failed < 5:
            return f"⚠️ **Login Activity**: {total_failed} failed login attempts detected. Normal activity level."
        elif total_failed < 20:
            recent_info = f"\n\n**Recent attempts**: {len(recent_attempts)} in logs" if recent_attempts else ""
            return f"🟡 **Moderate Risk**: {total_failed} failed login attempts detected. Monitor for brute force attacks.{recent_info}"
        else:
            return f"🚨 **HIGH RISK**: {total_failed} failed login attempts detected! Possible brute force attack in progress.\n\n**Immediate action required**: Review security logs and consider IP blocking."
    
    async def _handle_monitoring(self, state: WorkflowState) -> WorkflowState:
        """Handle system monitoring with intelligent LLM-driven action selection"""
        tool = self.tools.get("server_security")
        if tool:
            # Use LLM to determine what monitoring action to take
            action_prompt = f"""
User query: "{state["user_query"]}"

Available monitoring actions:
- check_network_connections: For network status, connections, traffic
- monitor_processes: For running processes, CPU usage, system activity  
- monitor_system_load: For RAM, memory, CPU, overall system performance

Respond with ONLY the action name that best matches the user's request.
"""
            
            messages = [
                {"role": "system", "content": "You are a system monitoring expert. Respond with only the action name."},
                {"role": "user", "content": action_prompt}
            ]
            
            llm_response = await self.llm.generate(messages)
            action = llm_response.content.strip().lower()
            
            # Execute the LLM-chosen action
            if "network" in action:
                result = await tool.check_network_connections()
                response = self._format_network_response(result, state["user_query"])
            elif "process" in action:
                result = await tool.monitor_processes()
                response = self._format_process_response(result, state["user_query"])
            else:  # Default to system load for memory/performance queries
                result = await tool.monitor_system_load()
                response = self._format_memory_response(result, state["user_query"])
            
            state["tool_result"] = response
        else:
            state["tool_result"] = "❌ Monitoring system is currently unavailable. Please try again later."
        
        state["final_response"] = state["tool_result"]
        return state
    
    async def _handle_scanning(self, state: WorkflowState) -> WorkflowState:
        """Handle security scanning with intelligent responses"""
        tool = self.tools.get("threat_detection")
        if tool:
            result = await tool.detect_threats("", "", "")
            response = self._format_scan_response(result, state["user_query"])
            state["tool_result"] = response
        else:
            # Fallback to advanced threat hunting
            tool = self.tools.get("advanced_threat_hunting")
            if tool:
                result = await tool.detect_threats("", "", "")
                response = self._format_scan_response(result, state["user_query"])
                state["tool_result"] = response
            else:
                state["tool_result"] = "❌ Security scanner is currently unavailable. Please try again later."
        
        state["final_response"] = state["tool_result"]
        return state
    
    async def _handle_reporting(self, state: WorkflowState) -> WorkflowState:
        """Handle reporting and dashboards with intelligent responses"""
        user_query = state["user_query"].lower()
        
        # Check if this is a PDF report generation request
        if ("generate" in user_query or "create" in user_query) and ("report" in user_query or "pdf" in user_query):
            try:
                from tools.report_generator import SecurityReportGenerator
                generator = SecurityReportGenerator()
                
                # Determine report type and time range from query
                report_type = "comprehensive"
                time_range = "24h"
                
                if "executive" in user_query:
                    report_type = "executive"
                elif "technical" in user_query:
                    report_type = "technical"
                elif "compliance" in user_query:
                    report_type = "compliance"
                
                if "week" in user_query:
                    time_range = "7d"
                elif "month" in user_query:
                    time_range = "30d"
                
                # Check if email is requested
                send_email = "email" in user_query or "send" in user_query
                recipient_email = None
                
                if send_email:
                    # Extract email from query or use default
                    import re
                    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                    emails = re.findall(email_pattern, state["user_query"])
                    if emails:
                        recipient_email = emails[0]
                    else:
                        # Use default email from settings
                        recipient_email = settings.email_to if hasattr(settings, 'email_to') else None
                
                # Generate PDF report
                pdf_path = await generator.generate_security_report(report_type, time_range)
                
                # Send email if requested
                email_result = None
                if send_email and recipient_email:
                    email_result = await generator.send_report_email(
                        pdf_path=pdf_path,
                        recipient_email=recipient_email,
                        report_type=f"{report_type.title()} Security Report"
                    )
                
                response = f"✅ **Security Report Generated Successfully**\n\n"
                response += f"📋 **Report Type**: {report_type.title()}\n"
                response += f"📅 **Time Range**: {time_range}\n"
                response += f"📄 **Format**: PDF\n\n"
                response += f"🔗 **Download**: Use the download endpoint with path: {pdf_path}\n\n"
                
                if email_result:
                    if email_result["success"]:
                        response += f"📧 **Email**: Report sent successfully to {recipient_email}\n\n"
                    else:
                        response += f"❌ **Email Error**: {email_result['error']}\n\n"
                elif send_email:
                    response += f"❌ **Email**: No recipient email found in query\n\n"
                
                response += "The report includes:\n"
                response += "• Executive summary of security events\n"
                response += "• Detailed incident analysis\n"
                response += "• Security recommendations\n"
                response += "• System health metrics"
                
            except Exception as e:
                response = f"❌ **Report Generation Failed**: {str(e)}"
        else:
            # Handle other reporting requests
            tool = self.tools.get("realtime_reporting")
            if tool:
                result = await tool.get_dashboard_data()
                response = self._format_dashboard_response(result, state["user_query"])
            else:
                response = "Reporting tool not available"
        
        state["tool_result"] = response
        state["final_response"] = response
        state["messages"].append(AIMessage(content=response))
        return state
    
    async def _handle_general(self, state: WorkflowState) -> WorkflowState:
        """Handle general cybersecurity questions"""
        user_query = state["user_query"].lower()
        
        # Check if this is a report generation request
        if ("generate" in user_query or "create" in user_query) and ("report" in user_query or "pdf" in user_query):
            try:
                from tools.report_generator import SecurityReportGenerator
                generator = SecurityReportGenerator()
                
                # Determine report type and time range from query
                report_type = "comprehensive"
                time_range = "24h"
                
                if "executive" in user_query:
                    report_type = "executive"
                elif "technical" in user_query:
                    report_type = "technical"
                elif "compliance" in user_query:
                    report_type = "compliance"
                
                if "week" in user_query:
                    time_range = "7d"
                elif "month" in user_query:
                    time_range = "30d"
                
                # Generate PDF report
                pdf_path = await generator.generate_security_report(report_type, time_range)
                
                response = f"✅ **Security Report Generated Successfully**\n\n"
                response += f"📋 **Report Type**: {report_type.title()}\n"
                response += f"📅 **Time Range**: {time_range}\n"
                response += f"📄 **Format**: PDF\n\n"
                response += f"🔗 **Download**: Use the download endpoint with path: {pdf_path}\n\n"
                response += "The report includes:\n"
                response += "• Executive summary of security events\n"
                response += "• Detailed incident analysis\n"
                response += "• Security recommendations\n"
                response += "• System health metrics"
                
                state["tool_result"] = response
                state["pdf_path"] = pdf_path  # Store for download
                
            except Exception as e:
                state["tool_result"] = f"❌ **Report Generation Failed**: {str(e)}"
        else:
            # Handle regular general questions
            tool = self.tools.get("llm_response")
            if tool:
                result = await tool.execute({"input": state["user_query"]})
                state["tool_result"] = result["result"]
            else:
                state["tool_result"] = "❌ General response system is currently unavailable. Please try again later."
        
        state["final_response"] = state["tool_result"]
        return state
    
    async def process_query(self, user_query: str) -> str:
        """Process a user query through the workflow"""
        initial_state = WorkflowState(
            messages=[],
            user_query=user_query,
            tool_choice="",
            tool_result="",
            final_response=""
        )
        
        final_state = await self.workflow.ainvoke(initial_state)
        return final_state["final_response"]
    
    def _format_network_response(self, result: Dict[str, Any], query: str) -> str:
        """Format network monitoring results intelligently"""
        total = result.get("total_connections", 0)
        external = len(result.get("external_connections", []))
        suspicious = len(result.get("suspicious_connections", []))
        
        if suspicious > 0:
            return f"🔴 **Network Alert**: Found {suspicious} suspicious connections out of {total} total connections. External connections: {external}. Immediate investigation recommended!"
        elif external > 10:
            return f"🟡 **Network Status**: Your network has {external} external connections (out of {total} total). This is higher than normal - monitor for unusual activity."
        else:
            return f"✅ **Network Healthy**: {total} active connections, {external} external. No suspicious activity detected. Your network appears secure."
    
    def _format_process_response(self, result: Dict[str, Any], query: str) -> str:
        """Format process monitoring results intelligently"""
        total = result.get("total_processes", 0)
        suspicious = len(result.get("suspicious_processes", []))
        high_cpu = len(result.get("high_cpu_processes", []))
        
        if suspicious > 0:
            return f"⚠️ **Process Alert**: Found {suspicious} suspicious processes out of {total} total. High CPU processes: {high_cpu}. Review recommended."
        elif high_cpu > 3:
            return f"🟡 **Performance Notice**: {high_cpu} processes using high CPU resources. Total processes: {total}. System may be under load."
        else:
            return f"✅ **System Normal**: {total} processes running smoothly. No suspicious activity or performance issues detected."
    
    def _format_memory_response(self, result: Dict[str, Any], query: str) -> str:
        """Format memory monitoring results intelligently"""
        memory_pct = result.get("memory_percent", 0)
        cpu_pct = result.get("cpu_percent", 0)
        available_gb = result.get("memory_available_gb", 0)
        load_avg = result.get("load_average", {})
        network_io = result.get("network_io", {})
        
        status = "🔴 Critical" if memory_pct > 85 or cpu_pct > 90 else "🟡 Warning" if memory_pct > 70 or cpu_pct > 70 else "✅ Healthy"
        
        response = f"{status} **System Status**:\n\n"
        response += f"**💾 Memory**: {memory_pct}% used, {available_gb:.1f}GB available\n"
        response += f"**🖥️ CPU**: {cpu_pct}% usage\n"
        
        if load_avg:
            response += f"**📊 Load Average**: 1min: {load_avg.get('1min', 0):.2f}, 5min: {load_avg.get('5min', 0):.2f}, 15min: {load_avg.get('15min', 0):.2f}\n"
        
        if network_io:
            sent_mb = network_io.get('bytes_sent', 0) / (1024*1024)
            recv_mb = network_io.get('bytes_recv', 0) / (1024*1024)
            response += f"**🌐 Network I/O**: Sent: {sent_mb:.1f}MB, Received: {recv_mb:.1f}MB\n"
        
        if 'Critical' in status:
            response += "\n⚠️ **Action Required**: System resources critically low!"
        elif 'Warning' in status:
            response += "\n📋 **Recommendation**: Monitor resource usage closely"
        else:
            response += "\n✨ **Status**: All systems operating normally"
            
        return response
    
    def _format_system_response(self, result: Dict[str, Any], query: str) -> str:
        """Format general system monitoring results intelligently"""
        memory_pct = result.get("memory_percent", 0)
        cpu_pct = result.get("cpu_percent", 0)
        load_avg = result.get("load_average", {}).get("1min", 0)
        
        status = "🔴 Critical" if memory_pct > 85 or cpu_pct > 90 else "🟡 Warning" if memory_pct > 70 or cpu_pct > 70 else "✅ Healthy"
        
        return f"{status} **System Status**: CPU {cpu_pct}%, RAM {memory_pct}%, Load {load_avg:.2f}. {'Immediate attention needed!' if 'Critical' in status else 'System running normally.' if 'Healthy' in status else 'Monitor closely.'}"
    
    def _format_scan_response(self, result: Dict[str, Any], query: str) -> str:
        """Format security scan results intelligently"""
        threats = result.get("threats_found", 0)
        threat_level = result.get("threat_level", "Unknown")
        
        if threats > 0:
            return f"🚨 **Security Scan Alert**: Found {threats} potential threats! Threat level: {threat_level}. Immediate action required to secure your system."
        else:
            return f"✅ **Security Scan Complete**: No threats detected. Threat level: {threat_level}. Your system appears secure and protected."
    
    def _format_dashboard_response(self, result: Dict[str, Any], query: str) -> str:
        """Format dashboard results intelligently"""
        # Check if raw data is requested
        if "raw" in query.lower():
            return json.dumps(result)
            
        if isinstance(result, dict) and "dashboard_data" in result:
            data = result["dashboard_data"]
            total_events = data.get("total_events", 0)
            severity = data.get("severity_breakdown", {})
            event_types = data.get("event_types", {})
            system_metrics = data.get("system_metrics", {})
            
            critical = severity.get("critical", 0)
            high = severity.get("high", 0)
            medium = severity.get("medium", 0)
            
            response = f"📊 **Security Dashboard Overview**:\n\n"
            
            # Threat level assessment
            if critical > 0:
                response += f"🔴 **CRITICAL ALERT**: {critical} critical incidents require immediate attention!\n"
            elif high > 5:
                response += f"🟡 **HIGH PRIORITY**: {high} high-severity incidents detected\n"
            else:
                response += f"✅ **STABLE**: Security posture is stable\n"
            
            # Event breakdown
            response += f"\n**📈 Event Summary**:\n"
            response += f"• Total Events: {total_events}\n"
            response += f"• Critical: {critical} | High: {high} | Medium: {medium}\n"
            
            # Event types
            if event_types:
                response += f"\n**🔍 Event Types**:\n"
                for event_type, count in list(event_types.items())[:3]:
                    response += f"• {event_type.replace('_', ' ').title()}: {count}\n"
            
            # System health
            if system_metrics:
                cpu = system_metrics.get("cpu_percent", 0)
                memory = system_metrics.get("memory_percent", 0)
                connections = system_metrics.get("network_connections", 0)
                response += f"\n**🖥️ System Health**:\n"
                response += f"• CPU: {cpu}% | Memory: {memory}% | Connections: {connections}\n"
            
            return response
        else:
            return f"📊 **Dashboard Data**: {str(result)[:300]}..." if len(str(result)) > 300 else f"📊 **Dashboard Data**: {result}"
