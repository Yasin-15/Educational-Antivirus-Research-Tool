"""
Integrated educational reporting system for the Educational Antivirus Research Tool.

This module combines report generation with educational content to provide
comprehensive learning-focused reports and explanations.
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from core.models import ScanResult, Detection
from core.logging_config import get_logger
from reporting.report_generator import ReportGenerator, ReportStatistics
from reporting.educational_content import EducationalDatabase, EducationalContentDisplay

logger = get_logger(__name__)


class EducationalReportSystem:
    """
    Integrated system that combines report generation with educational content
    to provide comprehensive learning-focused reports and explanations.
    """
    
    def __init__(self, reports_path: str = "reports"):
        """Initialize the educational report system.
        
        Args:
            reports_path: Directory to save reports
        """
        self.report_generator = ReportGenerator(reports_path)
        self.educational_database = EducationalDatabase()
        self.content_display = EducationalContentDisplay(self.educational_database)
        
        logger.info("EducationalReportSystem initialized")
    
    def generate_educational_report(self, scan_results: List[ScanResult],
                                  format_type: str = 'text',
                                  include_learning_content: bool = True) -> str:
        """Generate an educational report with learning content.
        
        Args:
            scan_results: List of scan results to include
            format_type: Output format ('json', 'csv', 'text')
            include_learning_content: Whether to include educational explanations
            
        Returns:
            Generated educational report content
        """
        if not scan_results:
            return self._generate_empty_educational_report(format_type)
        
        # Generate base report
        base_report = self.report_generator.generate_report(scan_results, format_type)
        
        if not include_learning_content or format_type != 'text':
            return base_report
        
        # Add educational content for text reports
        educational_content = self._generate_educational_content(scan_results)
        
        # Combine base report with educational content
        combined_report = base_report + "\n\n" + educational_content
        
        logger.info(f"Educational report generated with learning content")
        return combined_report
    
    def generate_threat_explanation_report(self, detections: List[Detection]) -> str:
        """Generate a detailed threat explanation report.
        
        Args:
            detections: List of detections to explain
            
        Returns:
            Detailed threat explanation report
        """
        if not detections:
            return "No threats detected - nothing to explain.\n"
        
        lines = []
        lines.append("THREAT EXPLANATION REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total threats analyzed: {len(detections)}")
        lines.append("")
        
        # Group detections by threat type for better organization
        threat_groups = {}
        for detection in detections:
            threat_name = detection.threat_name
            if threat_name not in threat_groups:
                threat_groups[threat_name] = []
            threat_groups[threat_name].append(detection)
        
        # Generate explanations for each threat type
        for i, (threat_name, threat_detections) in enumerate(threat_groups.items(), 1):
            lines.append(f"THREAT {i}: {threat_name}")
            lines.append("=" * 60)
            lines.append(f"Occurrences: {len(threat_detections)}")
            lines.append("")
            
            # Use the first detection as representative for explanation
            representative_detection = threat_detections[0]
            explanation = self.content_display.format_threat_explanation(representative_detection)
            lines.append(explanation)
            
            # List all affected files if multiple
            if len(threat_detections) > 1:
                lines.append("ALL AFFECTED FILES:")
                lines.append("-" * 30)
                for detection in threat_detections:
                    lines.append(f"  • {detection.file_path} (Risk: {detection.risk_score}/10)")
                lines.append("")
            
            lines.append("\n")
        
        # Add learning recommendations
        learning_recommendations = self.content_display.get_learning_recommendations(detections)
        lines.append(learning_recommendations)
        
        return "\n".join(lines)
    
    def generate_detection_method_guide(self) -> str:
        """Generate a comprehensive guide to detection methods.
        
        Returns:
            Detection method guide content
        """
        lines = []
        lines.append("DETECTION METHODS EDUCATIONAL GUIDE")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        lines.append("OVERVIEW")
        lines.append("-" * 40)
        lines.append("This guide explains the different methods used by antivirus software")
        lines.append("to detect threats. Understanding these methods helps you interpret")
        lines.append("scan results and learn about cybersecurity concepts.")
        lines.append("")
        
        # Generate content for each detection method
        for method, explanation in self.educational_database.detection_explanations.items():
            lines.append(f"{method.value.upper().replace('_', ' ')}")
            lines.append("=" * 50)
            lines.append("")
            
            lines.append("Description:")
            lines.append(explanation.method_description)
            lines.append("")
            
            lines.append("How it works:")
            lines.append(explanation.why_flagged)
            lines.append("")
            
            lines.append(f"Confidence Level: {explanation.confidence_level}")
            lines.append("")
            
            lines.append("Educational Context:")
            lines.append(explanation.educational_context)
            lines.append("")
            
            if explanation.learning_objectives:
                lines.append("Learning Objectives:")
                for objective in explanation.learning_objectives:
                    lines.append(f"  • {objective}")
                lines.append("")
            
            if explanation.further_reading:
                lines.append("Further Reading Topics:")
                for topic in explanation.further_reading:
                    lines.append(f"  • {topic}")
                lines.append("")
            
            lines.append("-" * 50)
            lines.append("")
        
        # Add practical tips
        lines.append("PRACTICAL TIPS FOR STUDENTS")
        lines.append("=" * 50)
        lines.append("")
        lines.append("1. Start with signature-based detection:")
        lines.append("   • Create EICAR test files to understand basic detection")
        lines.append("   • Learn how signature databases work")
        lines.append("   • Understand the importance of updates")
        lines.append("")
        lines.append("2. Explore behavioral analysis:")
        lines.append("   • Create files with high entropy")
        lines.append("   • Test different file extensions")
        lines.append("   • Understand false positive scenarios")
        lines.append("")
        lines.append("3. Combine multiple methods:")
        lines.append("   • See how different methods complement each other")
        lines.append("   • Learn about layered security approaches")
        lines.append("   • Practice threat assessment skills")
        lines.append("")
        
        return "\n".join(lines)
    
    def generate_threat_database_report(self) -> str:
        """Generate a report of all threats in the educational database.
        
        Returns:
            Threat database report content
        """
        lines = []
        lines.append("EDUCATIONAL THREAT DATABASE")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        # Statistics
        total_threats = len(self.educational_database.threat_info)
        categories = set(info.category for info in self.educational_database.threat_info.values())
        
        lines.append("DATABASE STATISTICS")
        lines.append("-" * 40)
        lines.append(f"Total threats: {total_threats}")
        lines.append(f"Categories: {len(categories)}")
        lines.append("")
        
        # Group by category
        category_groups = {}
        for threat_info in self.educational_database.threat_info.values():
            category = threat_info.category
            if category not in category_groups:
                category_groups[category] = []
            category_groups[category].append(threat_info)
        
        # Generate content for each category
        for category, threats in category_groups.items():
            lines.append(f"{category.value.upper().replace('_', ' ')} ({len(threats)} threats)")
            lines.append("=" * 60)
            lines.append("")
            
            for threat in sorted(threats, key=lambda x: x.severity_level, reverse=True):
                lines.append(f"THREAT: {threat.threat_name}")
                lines.append(f"Severity: {threat.severity_level}/10")
                lines.append(f"Description: {threat.description}")
                lines.append("")
                lines.append("How it works:")
                lines.append(threat.how_it_works)
                lines.append("")
                lines.append("Potential damage:")
                lines.append(threat.potential_damage)
                lines.append("")
                
                if threat.prevention_tips:
                    lines.append("Prevention tips:")
                    for tip in threat.prevention_tips:
                        lines.append(f"  • {tip}")
                    lines.append("")
                
                lines.append("Detection methods:")
                for method in threat.detection_methods:
                    lines.append(f"  • {method.value.replace('_', ' ').title()}")
                lines.append("")
                
                if threat.educational_notes:
                    lines.append("Educational notes:")
                    lines.append(threat.educational_notes)
                    lines.append("")
                
                if threat.real_world_examples:
                    lines.append("Real-world examples:")
                    for example in threat.real_world_examples:
                        lines.append(f"  • {example}")
                    lines.append("")
                
                lines.append("-" * 40)
                lines.append("")
        
        return "\n".join(lines)
    
    def save_educational_report(self, scan_results: List[ScanResult],
                               format_type: str = 'text',
                               filename: Optional[str] = None,
                               include_learning_content: bool = True) -> str:
        """Generate and save an educational report.
        
        Args:
            scan_results: List of scan results to include
            format_type: Output format
            filename: Output filename (auto-generated if None)
            include_learning_content: Whether to include educational content
            
        Returns:
            Path to saved report file
        """
        report_content = self.generate_educational_report(
            scan_results, format_type, include_learning_content
        )
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            extension = self.report_generator._get_file_extension(format_type)
            filename = f"educational_report_{timestamp}.{extension}"
        
        return self.report_generator.save_report(report_content, filename, format_type)
    
    def save_threat_explanation_report(self, detections: List[Detection],
                                     filename: Optional[str] = None) -> str:
        """Generate and save a threat explanation report.
        
        Args:
            detections: List of detections to explain
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to saved report file
        """
        report_content = self.generate_threat_explanation_report(detections)
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"threat_explanations_{timestamp}.txt"
        
        return self.report_generator.save_report(report_content, filename, 'text')
    
    def get_quick_threat_summary(self, detection: Detection) -> str:
        """Get a quick summary of a threat for immediate display.
        
        Args:
            detection: Detection to summarize
            
        Returns:
            Quick threat summary
        """
        return self.content_display.format_threat_summary(detection)
    
    def get_detailed_threat_explanation(self, detection: Detection) -> str:
        """Get a detailed explanation of a threat.
        
        Args:
            detection: Detection to explain
            
        Returns:
            Detailed threat explanation
        """
        return self.content_display.format_threat_explanation(detection)
    
    def list_educational_content(self) -> str:
        """List all available educational content.
        
        Returns:
            Formatted list of educational content
        """
        return self.content_display.list_available_educational_content()
    
    def get_learning_recommendations(self, scan_results: List[ScanResult]) -> str:
        """Get learning recommendations based on scan results.
        
        Args:
            scan_results: List of scan results to analyze
            
        Returns:
            Learning recommendations
        """
        all_detections = []
        for result in scan_results:
            all_detections.extend(result.detections)
        
        return self.content_display.get_learning_recommendations(all_detections)
    
    def _generate_educational_content(self, scan_results: List[ScanResult]) -> str:
        """Generate educational content section for reports.
        
        Args:
            scan_results: List of scan results to analyze
            
        Returns:
            Educational content section
        """
        lines = []
        lines.append("EDUCATIONAL CONTENT SECTION")
        lines.append("=" * 80)
        lines.append("")
        
        # Collect all detections
        all_detections = []
        for result in scan_results:
            all_detections.extend(result.detections)
        
        if not all_detections:
            lines.append("No threats detected in this scan.")
            lines.append("")
            lines.append("LEARNING OPPORTUNITIES:")
            lines.append("• Create test samples to practice threat detection")
            lines.append("• Learn about different types of malware")
            lines.append("• Understand how antivirus software works")
            lines.append("• Explore signature-based vs. behavioral detection")
            return "\n".join(lines)
        
        # Threat summaries
        lines.append("THREAT SUMMARIES")
        lines.append("-" * 40)
        
        unique_threats = {}
        for detection in all_detections:
            threat_name = detection.threat_name
            if threat_name not in unique_threats:
                unique_threats[threat_name] = []
            unique_threats[threat_name].append(detection)
        
        for threat_name, detections in unique_threats.items():
            representative = detections[0]
            summary = self.content_display.format_threat_summary(representative)
            lines.append(summary)
            if len(detections) > 1:
                lines.append(f"📊 Found in {len(detections)} files")
            lines.append("")
        
        # Learning recommendations
        learning_recs = self.content_display.get_learning_recommendations(all_detections)
        lines.append(learning_recs)
        
        # Detection method insights
        lines.append("")
        lines.append("DETECTION METHOD INSIGHTS")
        lines.append("-" * 40)
        
        method_counts = {}
        for detection in all_detections:
            explanation = self.educational_database.get_detection_explanation(detection)
            method = explanation.detection_method
            method_counts[method] = method_counts.get(method, 0) + 1
        
        for method, count in method_counts.items():
            method_name = method.value.replace('_', ' ').title()
            lines.append(f"• {method_name}: {count} detections")
            
            # Add brief explanation
            explanation = self.educational_database.detection_explanations.get(method)
            if explanation:
                lines.append(f"  {explanation.method_description[:100]}...")
        
        lines.append("")
        lines.append("💡 For detailed explanations of each threat, use the threat")
        lines.append("   explanation report feature or review individual detections.")
        
        return "\n".join(lines)
    
    def _generate_empty_educational_report(self, format_type: str) -> str:
        """Generate an empty educational report.
        
        Args:
            format_type: Output format
            
        Returns:
            Empty educational report content
        """
        base_empty = self.report_generator._generate_empty_report(format_type)
        
        if format_type != 'text':
            return base_empty
        
        # Add educational content to empty text report
        educational_content = """

EDUCATIONAL OPPORTUNITIES
=========================

Since no scan results are available, consider these learning activities:

GETTING STARTED:
• Create test samples using the sample management system
• Run your first scan on a test directory
• Learn about different threat types and detection methods

UNDERSTANDING ANTIVIRUS TECHNOLOGY:
• Study signature-based detection with EICAR test files
• Explore behavioral analysis with high-entropy files
• Learn about heuristic detection methods

HANDS-ON PRACTICE:
• Create custom test signatures
• Experiment with different scan settings
• Practice threat assessment and quarantine procedures

ADVANCED TOPICS:
• Study real-world malware families (safely)
• Learn about advanced persistent threats
• Understand the evolution of antivirus technology

For more information, use the educational content features of this tool
to access detailed explanations and learning materials.
"""
        
        return base_empty + educational_content
    
    def export_educational_database(self, file_path: Optional[str] = None) -> str:
        """Export the educational database to a file.
        
        Args:
            file_path: Path to save the database (auto-generated if None)
            
        Returns:
            Path to saved database file
        """
        if file_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_path = f"reports/educational_database_{timestamp}.json"
        
        # Ensure directory exists
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        
        self.educational_database.export_database(file_path)
        return file_path
    
    def import_educational_database(self, file_path: str) -> None:
        """Import educational database from a file.
        
        Args:
            file_path: Path to the database file
        """
        self.educational_database.import_database(file_path)
        # Update the content display system
        self.content_display.database = self.educational_database