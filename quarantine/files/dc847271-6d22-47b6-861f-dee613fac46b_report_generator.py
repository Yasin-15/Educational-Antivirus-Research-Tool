"""
Report generation system for the Educational Antivirus Research Tool.

This module provides comprehensive report generation capabilities with support
for multiple output formats (JSON, CSV, text) and detailed statistics calculation.
"""
import os
import json
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from dataclasses import asdict
import tempfile

from core.models import ScanResult, Detection, DetectionType, ScanStatus
from core.logging_config import get_logger

logger = get_logger(__name__)


class ReportStatistics:
    """Calculate and store scan statistics for reporting."""
    
    def __init__(self, scan_results: List[ScanResult]):
        """Initialize statistics from scan results.
        
        Args:
            scan_results: List of scan results to analyze
        """
        self.scan_results = scan_results
        self._calculate_statistics()
    
    def _calculate_statistics(self) -> None:
        """Calculate comprehensive statistics from scan results."""
        # Basic counts
        self.total_scans = len(self.scan_results)
        self.total_files_scanned = sum(result.total_files for result in self.scan_results)
        self.total_detections = sum(len(result.detections) for result in self.scan_results)
        self.total_errors = sum(len(result.errors) for result in self.scan_results)
        
        # Detection type breakdown
        signature_detections = 0
        behavioral_detections = 0
        
        for result in self.scan_results:
            for detection in result.detections:
                if detection.detection_type == DetectionType.SIGNATURE:
                    signature_detections += 1
                elif detection.detection_type == DetectionType.BEHAVIORAL:
                    behavioral_detections += 1
        
        self.signature_detections = signature_detections
        self.behavioral_detections = behavioral_detections
        
        # Risk score analysis
        all_risk_scores = []
        for result in self.scan_results:
            all_risk_scores.extend([d.risk_score for d in result.detections])
        
        if all_risk_scores:
            self.avg_risk_score = sum(all_risk_scores) / len(all_risk_scores)
            self.max_risk_score = max(all_risk_scores)
            self.min_risk_score = min(all_risk_scores)
            self.high_risk_detections = sum(1 for score in all_risk_scores if score >= 8)
            self.medium_risk_detections = sum(1 for score in all_risk_scores if 4 <= score < 8)
            self.low_risk_detections = sum(1 for score in all_risk_scores if score < 4)
        else:
            self.avg_risk_score = 0.0
            self.max_risk_score = 0
            self.min_risk_score = 0
            self.high_risk_detections = 0
            self.medium_risk_detections = 0
            self.low_risk_detections = 0
        
        # Time analysis
        completed_scans = [r for r in self.scan_results if r.end_time is not None]
        if completed_scans:
            scan_durations = [
                (r.end_time - r.start_time).total_seconds() 
                for r in completed_scans
            ]
            self.avg_scan_duration = sum(scan_durations) / len(scan_durations)
            self.total_scan_time = sum(scan_durations)
            
            # Calculate files per second
            if self.total_scan_time > 0:
                self.files_per_second = self.total_files_scanned / self.total_scan_time
            else:
                self.files_per_second = 0.0
        else:
            self.avg_scan_duration = 0.0
            self.total_scan_time = 0.0
            self.files_per_second = 0.0
        
        # Status breakdown
        self.successful_scans = sum(1 for r in self.scan_results if r.status == ScanStatus.COMPLETED)
        self.failed_scans = sum(1 for r in self.scan_results if r.status == ScanStatus.FAILED)
        
        # Most common threats
        threat_counts = {}
        for result in self.scan_results:
            for detection in result.detections:
                threat_name = detection.threat_name
                threat_counts[threat_name] = threat_counts.get(threat_name, 0) + 1
        
        self.most_common_threats = sorted(
            threat_counts.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]  # Top 10 most common threats
        
        # Detection rate
        if self.total_files_scanned > 0:
            self.detection_rate = (self.total_detections / self.total_files_scanned) * 100
        else:
            self.detection_rate = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert statistics to dictionary format."""
        return {
            'summary': {
                'total_scans': self.total_scans,
                'total_files_scanned': self.total_files_scanned,
                'total_detections': self.total_detections,
                'total_errors': self.total_errors,
                'detection_rate_percent': round(self.detection_rate, 2)
            },
            'detection_breakdown': {
                'signature_detections': self.signature_detections,
                'behavioral_detections': self.behavioral_detections
            },
            'risk_analysis': {
                'average_risk_score': round(self.avg_risk_score, 2),
                'max_risk_score': self.max_risk_score,
                'min_risk_score': self.min_risk_score,
                'high_risk_count': self.high_risk_detections,
                'medium_risk_count': self.medium_risk_detections,
                'low_risk_count': self.low_risk_detections
            },
            'performance': {
                'average_scan_duration_seconds': round(self.avg_scan_duration, 2),
                'total_scan_time_seconds': round(self.total_scan_time, 2),
                'files_per_second': round(self.files_per_second, 2)
            },
            'scan_status': {
                'successful_scans': self.successful_scans,
                'failed_scans': self.failed_scans
            },
            'most_common_threats': self.most_common_threats
        }


class ReportTemplate:
    """Base class for report templates."""
    
    def __init__(self, name: str, description: str):
        """Initialize report template.
        
        Args:
            name: Template name
            description: Template description
        """
        self.name = name
        self.description = description
    
    def generate(self, scan_results: List[ScanResult], statistics: ReportStatistics) -> str:
        """Generate report content.
        
        Args:
            scan_results: List of scan results
            statistics: Calculated statistics
            
        Returns:
            Generated report content
        """
        raise NotImplementedError("Subclasses must implement generate method")


class JSONReportTemplate(ReportTemplate):
    """JSON format report template."""
    
    def __init__(self):
        super().__init__("JSON", "Detailed JSON format report")
    
    def generate(self, scan_results: List[ScanResult], statistics: ReportStatistics) -> str:
        """Generate JSON report."""
        report_data = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'report_type': 'comprehensive_scan_report',
                'version': '1.0',
                'scan_count': len(scan_results)
            },
            'statistics': statistics.to_dict(),
            'scan_results': [result.to_dict() for result in scan_results]
        }
        
        return json.dumps(report_data, indent=2, ensure_ascii=False)


class CSVReportTemplate(ReportTemplate):
    """CSV format report template."""
    
    def __init__(self):
        super().__init__("CSV", "Tabular CSV format report")
    
    def generate(self, scan_results: List[ScanResult], statistics: ReportStatistics) -> str:
        """Generate CSV report."""
        # Create temporary file for CSV generation
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as temp_file:
            writer = csv.writer(temp_file)
            
            # Write header
            writer.writerow([
                'Scan ID', 'Start Time', 'End Time', 'Duration (seconds)',
                'Files Scanned', 'Detections Found', 'Errors', 'Status',
                'Detection File Path', 'Detection Type', 'Threat Name', 
                'Risk Score', 'Signature ID', 'Detection Time'
            ])
            
            # Write scan data with detections
            for result in scan_results:
                duration = 0
                if result.end_time:
                    duration = (result.end_time - result.start_time).total_seconds()
                
                if result.detections:
                    # Write one row per detection
                    for detection in result.detections:
                        writer.writerow([
                            result.scan_id,
                            result.start_time.isoformat(),
                            result.end_time.isoformat() if result.end_time else '',
                            duration,
                            result.total_files,
                            len(result.detections),
                            len(result.errors),
                            result.status.value,
                            detection.file_path,
                            detection.detection_type.value,
                            detection.threat_name,
                            detection.risk_score,
                            detection.signature_id or '',
                            detection.timestamp.isoformat()
                        ])
                else:
                    # Write scan row without detection details
                    writer.writerow([
                        result.scan_id,
                        result.start_time.isoformat(),
                        result.end_time.isoformat() if result.end_time else '',
                        duration,
                        result.total_files,
                        0,
                        len(result.errors),
                        result.status.value,
                        '', '', '', '', '', ''
                    ])
        
        # Read the CSV content
        with open(temp_file.name, 'r') as f:
            csv_content = f.read()
        
        # Clean up temporary file
        os.unlink(temp_file.name)
        
        return csv_content


class TextReportTemplate(ReportTemplate):
    """Human-readable text format report template."""
    
    def __init__(self):
        super().__init__("Text", "Human-readable text format report")
    
    def generate(self, scan_results: List[ScanResult], statistics: ReportStatistics) -> str:
        """Generate text report."""
        lines = []
        
        # Header
        lines.append("=" * 80)
        lines.append("EDUCATIONAL ANTIVIRUS RESEARCH TOOL - SCAN REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Report covers {len(scan_results)} scan(s)")
        lines.append("")
        
        # Executive Summary
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 40)
        lines.append(f"Total Files Scanned: {statistics.total_files_scanned:,}")
        lines.append(f"Total Detections: {statistics.total_detections:,}")
        lines.append(f"Detection Rate: {statistics.detection_rate:.2f}%")
        lines.append(f"Average Risk Score: {statistics.avg_risk_score:.2f}")
        lines.append(f"Scan Success Rate: {(statistics.successful_scans/statistics.total_scans*100):.1f}%")
        lines.append("")
        
        # Detection Breakdown
        lines.append("DETECTION ANALYSIS")
        lines.append("-" * 40)
        lines.append(f"Signature-based Detections: {statistics.signature_detections}")
        lines.append(f"Behavioral Detections: {statistics.behavioral_detections}")
        lines.append("")
        lines.append("Risk Level Distribution:")
        lines.append(f"  High Risk (8-10): {statistics.high_risk_detections}")
        lines.append(f"  Medium Risk (4-7): {statistics.medium_risk_detections}")
        lines.append(f"  Low Risk (1-3): {statistics.low_risk_detections}")
        lines.append("")
        
        # Performance Metrics
        lines.append("PERFORMANCE METRICS")
        lines.append("-" * 40)
        lines.append(f"Average Scan Duration: {statistics.avg_scan_duration:.2f} seconds")
        lines.append(f"Total Scan Time: {statistics.total_scan_time:.2f} seconds")
        lines.append(f"Scanning Speed: {statistics.files_per_second:.2f} files/second")
        lines.append("")
        
        # Most Common Threats
        if statistics.most_common_threats:
            lines.append("MOST COMMON THREATS")
            lines.append("-" * 40)
            for i, (threat_name, count) in enumerate(statistics.most_common_threats[:5], 1):
                lines.append(f"{i:2d}. {threat_name}: {count} occurrences")
            lines.append("")
        
        # Recent Scan Details
        lines.append("RECENT SCAN DETAILS")
        lines.append("-" * 40)
        
        # Show last 5 scans
        recent_scans = sorted(scan_results, key=lambda x: x.start_time, reverse=True)[:5]
        
        for scan in recent_scans:
            duration = "N/A"
            if scan.end_time:
                duration = f"{(scan.end_time - scan.start_time).total_seconds():.1f}s"
            
            lines.append(f"Scan ID: {scan.scan_id}")
            lines.append(f"  Time: {scan.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append(f"  Duration: {duration}")
            lines.append(f"  Files: {scan.total_files}, Detections: {len(scan.detections)}")
            lines.append(f"  Status: {scan.status.value}")
            
            if scan.detections:
                lines.append("  Threats Found:")
                for detection in scan.detections[:3]:  # Show first 3 detections
                    lines.append(f"    - {detection.threat_name} (Risk: {detection.risk_score})")
                    lines.append(f"      File: {detection.file_path}")
                if len(scan.detections) > 3:
                    lines.append(f"    ... and {len(scan.detections) - 3} more")
            lines.append("")
        
        # Recommendations
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 40)
        
        if statistics.detection_rate > 5:
            lines.append("⚠️  High detection rate detected. Consider:")
            lines.append("   - Reviewing quarantined files")
            lines.append("   - Updating signature database")
            lines.append("   - Checking for false positives")
        elif statistics.detection_rate == 0:
            lines.append("✅ No threats detected in recent scans.")
            lines.append("   - System appears clean")
            lines.append("   - Consider periodic rescanning")
        else:
            lines.append("ℹ️  Normal detection rate observed.")
            lines.append("   - Continue regular scanning")
            lines.append("   - Monitor for changes")
        
        if statistics.high_risk_detections > 0:
            lines.append(f"🚨 {statistics.high_risk_detections} high-risk threats found!")
            lines.append("   - Review and quarantine immediately")
            lines.append("   - Consider system isolation")
        
        lines.append("")
        lines.append("=" * 80)
        lines.append("End of Report")
        lines.append("=" * 80)
        
        return "\n".join(lines)


class ReportGenerator:
    """Main report generation system."""
    
    def __init__(self, reports_path: str = "reports"):
        """Initialize report generator.
        
        Args:
            reports_path: Directory to save reports
        """
        self.reports_path = Path(reports_path)
        self.reports_path.mkdir(exist_ok=True)
        
        # Initialize available templates
        self.templates = {
            'json': JSONReportTemplate(),
            'csv': CSVReportTemplate(),
            'text': TextReportTemplate()
        }
        
        logger.info(f"ReportGenerator initialized with path: {self.reports_path}")
    
    def generate_report(self, scan_results: List[ScanResult], 
                       format_type: str = 'text',
                       template_name: Optional[str] = None) -> str:
        """Generate a report from scan results.
        
        Args:
            scan_results: List of scan results to include in report
            format_type: Output format ('json', 'csv', 'text')
            template_name: Specific template name (optional)
            
        Returns:
            Generated report content as string
            
        Raises:
            ValueError: If format_type is not supported
        """
        if not scan_results:
            logger.warning("No scan results provided for report generation")
            return self._generate_empty_report(format_type)
        
        # Validate format
        if format_type not in self.templates:
            raise ValueError(f"Unsupported format: {format_type}. Available: {list(self.templates.keys())}")
        
        # Calculate statistics
        statistics = ReportStatistics(scan_results)
        
        # Get template
        template = self.templates[format_type]
        
        # Generate report
        logger.info(f"Generating {format_type} report for {len(scan_results)} scan results")
        report_content = template.generate(scan_results, statistics)
        
        logger.info(f"Report generated successfully ({len(report_content)} characters)")
        return report_content
    
    def save_report(self, report_content: str, filename: Optional[str] = None,
                   format_type: str = 'text') -> str:
        """Save report content to file.
        
        Args:
            report_content: Report content to save
            filename: Output filename (auto-generated if None)
            format_type: Report format for file extension
            
        Returns:
            Path to saved report file
            
        Raises:
            IOError: If file saving fails
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            extension = self._get_file_extension(format_type)
            filename = f"antivirus_report_{timestamp}.{extension}"
        
        output_path = self.reports_path / filename
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            logger.info(f"Report saved to: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Failed to save report to {output_path}: {e}")
            raise IOError(f"Failed to save report: {e}")
    
    def generate_and_save_report(self, scan_results: List[ScanResult],
                                format_type: str = 'text',
                                filename: Optional[str] = None) -> str:
        """Generate and save a report in one operation.
        
        Args:
            scan_results: List of scan results to include
            format_type: Output format
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to saved report file
        """
        report_content = self.generate_report(scan_results, format_type)
        return self.save_report(report_content, filename, format_type)
    
    def get_available_formats(self) -> List[str]:
        """Get list of available report formats.
        
        Returns:
            List of format names
        """
        return list(self.templates.keys())
    
    def get_template_info(self, format_type: str) -> Dict[str, str]:
        """Get information about a specific template.
        
        Args:
            format_type: Format type to get info for
            
        Returns:
            Dictionary with template information
            
        Raises:
            ValueError: If format_type is not supported
        """
        if format_type not in self.templates:
            raise ValueError(f"Unsupported format: {format_type}")
        
        template = self.templates[format_type]
        return {
            'name': template.name,
            'description': template.description,
            'format': format_type
        }
    
    def list_saved_reports(self) -> List[Dict[str, Any]]:
        """List all saved reports in the reports directory.
        
        Returns:
            List of report file information
        """
        reports = []
        
        try:
            for file_path in self.reports_path.glob("*"):
                if file_path.is_file():
                    stat = file_path.stat()
                    reports.append({
                        'filename': file_path.name,
                        'path': str(file_path),
                        'size_bytes': stat.st_size,
                        'created': datetime.fromtimestamp(stat.st_ctime),
                        'modified': datetime.fromtimestamp(stat.st_mtime),
                        'format': self._detect_format_from_filename(file_path.name)
                    })
            
            # Sort by modification time (newest first)
            reports.sort(key=lambda x: x['modified'], reverse=True)
            
        except Exception as e:
            logger.error(f"Failed to list saved reports: {e}")
        
        return reports
    
    def _generate_empty_report(self, format_type: str) -> str:
        """Generate an empty report when no scan results are available.
        
        Args:
            format_type: Output format
            
        Returns:
            Empty report content
        """
        if format_type == 'json':
            return json.dumps({
                'report_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'report_type': 'empty_report',
                    'message': 'No scan results available'
                },
                'statistics': {},
                'scan_results': []
            }, indent=2)
        
        elif format_type == 'csv':
            return "message\nNo scan results available for CSV report\n"
        
        else:  # text format
            return f"""
Educational Antivirus Research Tool - Empty Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

No scan results available for report generation.
Please run some scans first and then generate a report.
"""
    
    def _get_file_extension(self, format_type: str) -> str:
        """Get appropriate file extension for format type.
        
        Args:
            format_type: Report format
            
        Returns:
            File extension without dot
        """
        extensions = {
            'json': 'json',
            'csv': 'csv',
            'text': 'txt'
        }
        return extensions.get(format_type, 'txt')
    
    def _detect_format_from_filename(self, filename: str) -> str:
        """Detect report format from filename.
        
        Args:
            filename: Name of the file
            
        Returns:
            Detected format type
        """
        extension = Path(filename).suffix.lower()
        format_map = {
            '.json': 'json',
            '.csv': 'csv',
            '.txt': 'text'
        }
        return format_map.get(extension, 'unknown')