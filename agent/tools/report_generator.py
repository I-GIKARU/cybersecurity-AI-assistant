from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from datetime import datetime
import os
import tempfile
from core.postgres_db import db

class SecurityReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue
        )
        
    async def generate_security_report(self, report_type="comprehensive", time_range="24h"):
        """Generate a comprehensive security report as PDF"""
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        temp_path = temp_file.name
        temp_file.close()
        
        # Create PDF document
        doc = SimpleDocTemplate(temp_path, pagesize=A4)
        story = []
        
        # Title
        title = Paragraph("🔒 Cybersecurity Security Report", self.title_style)
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Report metadata
        report_info = [
            ["Report Type:", report_type.title()],
            ["Time Range:", time_range],
            ["Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["System:", "AI-Powered Cybersecurity Platform"]
        ]
        
        info_table = Table(report_info, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(info_table)
        story.append(Spacer(1, 30))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['Heading2']))
        
        # Get security events from database
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
