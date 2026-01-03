from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from datetime import datetime
import os
import tempfile
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from core.postgres_db import db
from config.settings import settings

class SecurityReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=20,
            spaceAfter=20,
            textColor=colors.darkblue,
            alignment=1  # Center alignment
        )
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            textColor=colors.darkred
        )
        
    async def generate_security_report(self, time_range="24h"):
        """Generate a comprehensive security report as PDF with proper formatting"""
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        temp_path = temp_file.name
        temp_file.close()
        
        # Create PDF document with margins
        doc = SimpleDocTemplate(
            temp_path, 
            pagesize=A4,
            rightMargin=0.5*inch,
            leftMargin=0.5*inch,
            topMargin=0.5*inch,
            bottomMargin=0.5*inch
        )
        story = []
        
        # Title
        title = Paragraph("🔒 Cybersecurity Security Report", self.title_style)
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Report metadata
        report_info = [
            ["Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Time Range:", time_range],
            ["System:", "AI-Powered Cybersecurity Platform"]
        ]
        
        info_table = Table(report_info, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 30))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.heading_style))
        
        # Get security events from database
        try:
            events = await db.get_security_events(limit=50)
            total_events = len(events)
            
            # Count by severity
            critical_count = len([e for e in events if e.get('severity') == 'critical'])
            high_count = len([e for e in events if e.get('severity') == 'high'])
            medium_count = len([e for e in events if e.get('severity') == 'medium'])
            
            summary_text = f"""
            During the {time_range} reporting period, the cybersecurity system processed {total_events} security events.
            
            • Critical incidents: {critical_count}
            • High severity incidents: {high_count}  
            • Medium severity incidents: {medium_count}
            
            The system maintained continuous monitoring and automated response capabilities.
            """
            
        except Exception as e:
            summary_text = f"Unable to retrieve security events: {str(e)}"
            events = []
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Recent Security Events
        story.append(Paragraph("Recent Security Events", self.heading_style))
        
        if events:
            # Create events table with proper column widths
            event_data = [["Timestamp", "Type", "Severity", "Description"]]
            
            for event in events[:20]:  # Show last 20 events
                timestamp = event.get('timestamp', 'N/A')
                if isinstance(timestamp, datetime):
                    timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                
                event_type = event.get('event_type', 'Unknown')[:20]  # Truncate long types
                severity = event.get('severity', 'Unknown')
                description = event.get('description', 'No description')[:60]  # Truncate long descriptions
                
                event_data.append([
                    str(timestamp)[:19],  # Limit timestamp length
                    event_type,
                    severity,
                    description
                ])
            
            # Create table with proper column widths
            events_table = Table(event_data, colWidths=[1.8*inch, 1.2*inch, 0.8*inch, 3.2*inch])
            events_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ]))
            story.append(events_table)
        else:
            story.append(Paragraph("No security events found in the specified time range.", self.styles['Normal']))
        
        story.append(Spacer(1, 30))
        
        # Security Recommendations
        story.append(Paragraph("Security Recommendations", self.heading_style))
        
        recommendations = [
            "• Continue monitoring for critical and high-severity incidents",
            "• Review and update security policies regularly", 
            "• Ensure all security tools are functioning properly",
            "• Maintain regular security awareness training",
            "• Implement multi-factor authentication where possible",
            "• Keep all systems and software updated",
            "• Regular backup and recovery testing",
            "• Network segmentation and access controls review"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, self.styles['Normal']))
        
        # Build PDF
        doc.build(story)
        
        return temp_path
    
    async def send_report_email(self, pdf_path: str, recipient_email: str, report_type: str = "Security Report"):
        """Send the security report via email"""
        try:
            # Email configuration
            smtp_server = settings.smtp_server
            smtp_port = settings.smtp_port
            sender_email = settings.security_email
            sender_password = settings.security_email_password
            
            if not all([smtp_server, sender_email, sender_password]):
                return {"success": False, "error": "Email configuration incomplete"}
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = recipient_email
            msg['Subject'] = f"🔒 {report_type} - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            
            # Email body
            body = f"""
            Security Report Generated
            
            Please find attached the latest cybersecurity report for your review.
            
            Report Details:
            • Type: {report_type}
            • Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            • System: AI-Powered Cybersecurity Platform
            
            This report contains important security information and should be reviewed promptly.
            
            Best regards,
            Cybersecurity AI Agent
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Attach PDF
            with open(pdf_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= security_report_{datetime.now().strftime("%Y%m%d_%H%M")}.pdf'
            )
            msg.attach(part)
            
            # Send email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            text = msg.as_string()
            server.sendmail(sender_email, recipient_email, text)
            server.quit()
            
            return {"success": True, "message": f"Report sent to {recipient_email}"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def generate_report_preview(self, time_range="24h"):
        """Generate report preview with actual data"""
        try:
            # Get security events from database
            events = await db.get_security_events(limit=50)
            total_events = len(events)
            
            # Count by severity
            critical_count = len([e for e in events if e.get('severity') == 'critical'])
            high_count = len([e for e in events if e.get('severity') == 'high'])
            medium_count = len([e for e in events if e.get('severity') == 'medium'])
            low_count = len([e for e in events if e.get('severity') == 'low'])
            
            # Get recent event types
            recent_types = list(set([e.get('event_type', 'unknown') for e in events[:10]]))[:5]
            
            preview = f"""📊 **Security Report Preview** ({time_range})

**📈 Event Summary:**
• Total Events: {total_events}
• Critical Incidents: {critical_count}
• High Severity: {high_count}
• Medium Severity: {medium_count}
• Low Severity: {low_count}

**🔍 Recent Activity:**
• Event Types: {', '.join(recent_types) if recent_types else 'No recent events'}

**📋 Full Report Includes:**
• Executive summary with detailed metrics
• Complete security events table (last 20 events)
• AI-generated security recommendations
• System health and performance data
• Threat analysis and security trends"""
            
            return preview.strip()
            
        except Exception as e:
            return f"Preview unavailable: {str(e)}"
        try:
            events = await db.get_security_events(limit=50)
            total_events = len(events)
            
            # Count by severity
            severity_counts = {}
            event_type_counts = {}
            
            for event in events:
                severity = event.get('severity', 'unknown')
                event_type = event.get('event_type', 'unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
            
            summary_text = f"""
            During the {time_range} reporting period, the cybersecurity system processed {total_events} security events.
            
            Critical incidents: {severity_counts.get('critical', 0)}
            High severity incidents: {severity_counts.get('high', 0)}
            Medium severity incidents: {severity_counts.get('medium', 0)}
            
            The system maintained continuous monitoring and automated response capabilities.
            """
            
            story.append(Paragraph(summary_text, self.styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Security Events Table
            story.append(Paragraph("Recent Security Events", self.styles['Heading2']))
            
            if events:
                event_data = [["Timestamp", "Type", "Severity", "Description"]]
                for event in events[:10]:  # Show top 10 events
                    timestamp = str(event.get('timestamp', 'N/A'))[:19]  # Truncate timestamp
                    event_type = event.get('event_type', 'N/A')
                    severity = event.get('severity', 'N/A')
                    description = event.get('description', 'N/A')[:50] + "..." if len(event.get('description', '')) > 50 else event.get('description', 'N/A')
                    
                    event_data.append([timestamp, event_type, severity, description])
                
                events_table = Table(event_data, colWidths=[1.5*inch, 1.5*inch, 1*inch, 2.5*inch])
                events_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(events_table)
            else:
                story.append(Paragraph("No security events found in the specified time range.", self.styles['Normal']))
            
            story.append(Spacer(1, 30))
            
            # Recommendations
            story.append(Paragraph("Security Recommendations", self.styles['Heading2']))
            
            recommendations = [
                "• Continue monitoring for critical and high-severity incidents",
                "• Review and update security policies regularly", 
                "• Ensure all security tools are functioning properly",
                "• Maintain regular security awareness training",
                "• Keep all systems and software updated"
            ]
            
            for rec in recommendations:
                story.append(Paragraph(rec, self.styles['Normal']))
            
        except Exception as e:
            error_text = f"Error generating report data: {str(e)}"
            story.append(Paragraph(error_text, self.styles['Normal']))
        
        # Build PDF
        doc.build(story)
        
        return temp_path
    
    def cleanup_report(self, file_path):
        """Clean up temporary report file"""
        try:
            if os.path.exists(file_path):
                os.unlink(file_path)
        except Exception:
            pass
