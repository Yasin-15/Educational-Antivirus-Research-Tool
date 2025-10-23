#!/usr/bin/env python3
"""
Real-Time GUI Dashboard for Educational Antivirus Tool.

This module provides a cross-platform desktop interface using tkinter
for monitoring, scanning, and managing the antivirus system.
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import queue
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import json

from core.models import ScanResult, Detection, QuarantineEntry
from core.config import ConfigManager


class AntivirusDashboard:
    """Main GUI dashboard for the antivirus tool."""
    
    def __init__(self, config=None, scanner_engine=None, quarantine_manager=None, realtime_manager=None):
        """Initialize the dashboard."""
        self.config = config
        self.scanner_engine = scanner_engine
        self.quarantine_manager = quarantine_manager
        self.realtime_manager = realtime_manager
        
        # GUI state
        self.root = None
        self.is_running = False
        self.update_queue = queue.Queue()
        
        # Statistics
        self.stats = {
            'scans_performed': 0,
            'threats_detected': 0,
            'files_quarantined': 0,
            'realtime_active': False
        }
        
        # Create GUI
        self._create_gui()
    
    def _create_gui(self):
        """Create the main GUI interface."""
        self.root = tk.Tk()
        self.root.title("Educational Antivirus Tool - Dashboard")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Create main layout
        self._create_menu()
        self._create_toolbar()
        self._create_main_content()
        self._create_status_bar()
        
        # Start update loop
        self._start_update_loop()
    
    def _create_menu(self):
        """Create the menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Scan File...", command=self._scan_file_dialog)
        file_menu.add_command(label="Scan Folder...", command=self._scan_folder_dialog)
        file_menu.add_separator()
        file_menu.add_command(label="Export Report...", command=self._export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_closing)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Quarantine Manager", command=self._show_quarantine_manager)
        tools_menu.add_command(label="Real-Time Protection", command=self._toggle_realtime_protection)
        tools_menu.add_command(label="Settings", command=self._show_settings)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about)
        help_menu.add_command(label="User Guide", command=self._show_user_guide)
    
    def _create_toolbar(self):
        """Create the toolbar."""
        toolbar_frame = ttk.Frame(self.root)
        toolbar_frame.pack(fill=tk.X, padx=5, pady=2)
        
        # Scan buttons
        ttk.Button(toolbar_frame, text="🔍 Quick Scan", command=self._quick_scan).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar_frame, text="📁 Scan Folder", command=self._scan_folder_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar_frame, text="🔒 Quarantine", command=self._show_quarantine_manager).pack(side=tk.LEFT, padx=2)
        
        # Separator
        ttk.Separator(toolbar_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)
        
        # Real-time protection toggle
        self.realtime_var = tk.BooleanVar()
        self.realtime_checkbox = ttk.Checkbutton(
            toolbar_frame, 
            text="🛡️ Real-Time Protection", 
            variable=self.realtime_var,
            command=self._toggle_realtime_protection
        )
        self.realtime_checkbox.pack(side=tk.LEFT, padx=2)
        
        # Status indicator
        self.status_indicator = ttk.Label(toolbar_frame, text="●", foreground="red")
        self.status_indicator.pack(side=tk.RIGHT, padx=5)
        
        ttk.Label(toolbar_frame, text="Status:").pack(side=tk.RIGHT)
    
    def _create_main_content(self):
        """Create the main content area."""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Dashboard tab
        self._create_dashboard_tab()
        
        # Scan Results tab
        self._create_scan_results_tab()
        
        # Real-Time Monitor tab
        self._create_realtime_tab()
        
        # Logs tab
        self._create_logs_tab()
    
    def _create_dashboard_tab(self):
        """Create the main dashboard tab."""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(dashboard_frame, text="System Statistics")
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Create statistics grid
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.X, padx=10, pady=10)
        
        # Statistics labels
        self.stats_labels = {}
        
        # Row 1
        ttk.Label(stats_grid, text="Scans Performed:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.stats_labels['scans'] = ttk.Label(stats_grid, text="0", font=('Arial', 12, 'bold'))
        self.stats_labels['scans'].grid(row=0, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(stats_grid, text="Threats Detected:").grid(row=0, column=2, sticky=tk.W, padx=20)
        self.stats_labels['threats'] = ttk.Label(stats_grid, text="0", font=('Arial', 12, 'bold'), foreground="red")
        self.stats_labels['threats'].grid(row=0, column=3, sticky=tk.W, padx=5)
        
        # Row 2
        ttk.Label(stats_grid, text="Files Quarantined:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.stats_labels['quarantined'] = ttk.Label(stats_grid, text="0", font=('Arial', 12, 'bold'))
        self.stats_labels['quarantined'].grid(row=1, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(stats_grid, text="Real-Time Status:").grid(row=1, column=2, sticky=tk.W, padx=20)
        self.stats_labels['realtime'] = ttk.Label(stats_grid, text="Inactive", font=('Arial', 12, 'bold'))
        self.stats_labels['realtime'].grid(row=1, column=3, sticky=tk.W, padx=5)
        
        # Quick actions frame
        actions_frame = ttk.LabelFrame(dashboard_frame, text="Quick Actions")
        actions_frame.pack(fill=tk.X, padx=10, pady=5)
        
        actions_grid = ttk.Frame(actions_frame)
        actions_grid.pack(fill=tk.X, padx=10, pady=10)
        
        # Action buttons
        ttk.Button(actions_grid, text="🔍 Scan Downloads Folder", 
                  command=self._scan_downloads).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_grid, text="🔍 Scan Desktop", 
                  command=self._scan_desktop).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_grid, text="🧹 Clean Temporary Files", 
                  command=self._clean_temp_files).pack(side=tk.LEFT, padx=5)
        
        # Recent activity frame
        activity_frame = ttk.LabelFrame(dashboard_frame, text="Recent Activity")
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Activity list
        self.activity_tree = ttk.Treeview(activity_frame, columns=('Time', 'Event', 'Details'), show='headings')
        self.activity_tree.heading('Time', text='Time')
        self.activity_tree.heading('Event', text='Event')
        self.activity_tree.heading('Details', text='Details')
        
        self.activity_tree.column('Time', width=150)
        self.activity_tree.column('Event', width=150)
        self.activity_tree.column('Details', width=400)
        
        # Scrollbar for activity list
        activity_scrollbar = ttk.Scrollbar(activity_frame, orient=tk.VERTICAL, command=self.activity_tree.yview)
        self.activity_tree.configure(yscrollcommand=activity_scrollbar.set)
        
        self.activity_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        activity_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def _create_scan_results_tab(self):
        """Create the scan results tab."""
        scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text="Scan Results")
        
        # Scan controls
        controls_frame = ttk.Frame(scan_frame)
        controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(controls_frame, text="Scan Path:").pack(side=tk.LEFT)
        self.scan_path_var = tk.StringVar()
        self.scan_path_entry = ttk.Entry(controls_frame, textvariable=self.scan_path_var, width=50)
        self.scan_path_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        ttk.Button(controls_frame, text="Browse", command=self._browse_scan_path).pack(side=tk.LEFT, padx=2)
        ttk.Button(controls_frame, text="Scan", command=self._start_scan).pack(side=tk.LEFT, padx=2)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(scan_frame, variable=self.progress_var, mode='determinate')
        self.progress_bar.pack(fill=tk.X, padx=10, pady=2)
        
        # Scan status
        self.scan_status_var = tk.StringVar(value="Ready to scan")
        ttk.Label(scan_frame, textvariable=self.scan_status_var).pack(padx=10, pady=2)
        
        # Results tree
        results_frame = ttk.LabelFrame(scan_frame, text="Scan Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.results_tree = ttk.Treeview(results_frame, columns=('File', 'Threat', 'Risk', 'Action'), show='headings')
        self.results_tree.heading('File', text='File Path')
        self.results_tree.heading('Threat', text='Threat Name')
        self.results_tree.heading('Risk', text='Risk Score')
        self.results_tree.heading('Action', text='Action')
        
        self.results_tree.column('File', width=300)
        self.results_tree.column('Threat', width=200)
        self.results_tree.column('Risk', width=80)
        self.results_tree.column('Action', width=100)
        
        # Results scrollbar
        results_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Context menu for results
        self.results_context_menu = tk.Menu(self.root, tearoff=0)
        self.results_context_menu.add_command(label="Quarantine", command=self._quarantine_selected)
        self.results_context_menu.add_command(label="Ignore", command=self._ignore_selected)
        self.results_context_menu.add_command(label="View Details", command=self._view_details)
        
        self.results_tree.bind("<Button-3>", self._show_results_context_menu)
    
    def _create_realtime_tab(self):
        """Create the real-time monitoring tab."""
        realtime_frame = ttk.Frame(self.notebook)
        self.notebook.add(realtime_frame, text="Real-Time Monitor")
        
        # Controls
        controls_frame = ttk.Frame(realtime_frame)
        controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.realtime_status_var = tk.StringVar(value="Real-time protection is inactive")
        ttk.Label(controls_frame, textvariable=self.realtime_status_var, font=('Arial', 12)).pack(side=tk.LEFT)
        
        ttk.Button(controls_frame, text="Start Protection", 
                  command=self._start_realtime_protection).pack(side=tk.RIGHT, padx=2)
        ttk.Button(controls_frame, text="Stop Protection", 
                  command=self._stop_realtime_protection).pack(side=tk.RIGHT, padx=2)
        
        # Monitored paths
        paths_frame = ttk.LabelFrame(realtime_frame, text="Monitored Paths")
        paths_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.paths_listbox = tk.Listbox(paths_frame, height=4)
        self.paths_listbox.pack(fill=tk.X, padx=5, pady=5)
        
        paths_buttons = ttk.Frame(paths_frame)
        paths_buttons.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Button(paths_buttons, text="Add Path", command=self._add_monitor_path).pack(side=tk.LEFT, padx=2)
        ttk.Button(paths_buttons, text="Remove Path", command=self._remove_monitor_path).pack(side=tk.LEFT, padx=2)
        
        # Real-time events
        events_frame = ttk.LabelFrame(realtime_frame, text="Real-Time Events")
        events_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.events_tree = ttk.Treeview(events_frame, columns=('Time', 'Event', 'File', 'Action'), show='headings')
        self.events_tree.heading('Time', text='Time')
        self.events_tree.heading('Event', text='Event Type')
        self.events_tree.heading('File', text='File Path')
        self.events_tree.heading('Action', text='Action Taken')
        
        self.events_tree.column('Time', width=150)
        self.events_tree.column('Event', width=100)
        self.events_tree.column('File', width=300)
        self.events_tree.column('Action', width=150)
        
        events_scrollbar = ttk.Scrollbar(events_frame, orient=tk.VERTICAL, command=self.events_tree.yview)
        self.events_tree.configure(yscrollcommand=events_scrollbar.set)
        
        self.events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        events_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def _create_logs_tab(self):
        """Create the logs tab."""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Logs")
        
        # Log controls
        log_controls = ttk.Frame(logs_frame)
        log_controls.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(log_controls, text="Log Level:").pack(side=tk.LEFT)
        self.log_level_var = tk.StringVar(value="INFO")
        log_level_combo = ttk.Combobox(log_controls, textvariable=self.log_level_var, 
                                      values=["DEBUG", "INFO", "WARNING", "ERROR"], width=10)
        log_level_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(log_controls, text="Clear Logs", command=self._clear_logs).pack(side=tk.RIGHT, padx=2)
        ttk.Button(log_controls, text="Export Logs", command=self._export_logs).pack(side=tk.RIGHT, padx=2)
        
        # Log display
        self.log_text = scrolledtext.ScrolledText(logs_frame, wrap=tk.WORD, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Configure log text tags for different levels
        self.log_text.tag_configure("ERROR", foreground="red")
        self.log_text.tag_configure("WARNING", foreground="orange")
        self.log_text.tag_configure("INFO", foreground="blue")
        self.log_text.tag_configure("DEBUG", foreground="gray")
    
    def _create_status_bar(self):
        """Create the status bar."""
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_text = tk.StringVar(value="Ready")
        ttk.Label(self.status_bar, textvariable=self.status_text).pack(side=tk.LEFT, padx=5)
        
        # Progress indicator
        self.status_progress = ttk.Progressbar(self.status_bar, mode='indeterminate', length=100)
        self.status_progress.pack(side=tk.RIGHT, padx=5)
    
    def _start_update_loop(self):
        """Start the GUI update loop."""
        self._update_gui()
        self.root.after(1000, self._start_update_loop)  # Update every second
    
    def _update_gui(self):
        """Update GUI elements."""
        try:
            # Process any queued updates
            while not self.update_queue.empty():
                update = self.update_queue.get_nowait()
                self._process_update(update)
            
            # Update statistics
            self._update_statistics()
            
            # Update real-time status
            self._update_realtime_status()
            
        except queue.Empty:
            pass
        except Exception as e:
            self._log_message(f"GUI update error: {e}", "ERROR")
    
    def _process_update(self, update: Dict[str, Any]):
        """Process a GUI update."""
        update_type = update.get('type')
        
        if update_type == 'scan_progress':
            self.progress_var.set(update['progress'])
            self.scan_status_var.set(update['status'])
        
        elif update_type == 'scan_result':
            self._add_scan_result(update['result'])
        
        elif update_type == 'realtime_event':
            self._add_realtime_event(update['event'])
        
        elif update_type == 'log_message':
            self._log_message(update['message'], update['level'])
        
        elif update_type == 'activity':
            self._add_activity(update['event'], update['details'])
    
    def _update_statistics(self):
        """Update statistics display."""
        self.stats_labels['scans'].config(text=str(self.stats['scans_performed']))
        self.stats_labels['threats'].config(text=str(self.stats['threats_detected']))
        self.stats_labels['quarantined'].config(text=str(self.stats['files_quarantined']))
        
        if self.stats['realtime_active']:
            self.stats_labels['realtime'].config(text="Active", foreground="green")
            self.status_indicator.config(text="●", foreground="green")
        else:
            self.stats_labels['realtime'].config(text="Inactive", foreground="red")
            self.status_indicator.config(text="●", foreground="red")
    
    def _update_realtime_status(self):
        """Update real-time protection status."""
        if self.realtime_manager:
            status = self.realtime_manager.get_status()
            self.stats['realtime_active'] = status['active']
            
            if status['active']:
                self.realtime_status_var.set("Real-time protection is ACTIVE")
                self.realtime_var.set(True)
            else:
                self.realtime_status_var.set("Real-time protection is INACTIVE")
                self.realtime_var.set(False)
    
    def _scan_file_dialog(self):
        """Open file dialog for scanning a single file."""
        file_path = filedialog.askopenfilename(
            title="Select file to scan",
            filetypes=[("All files", "*.*")]
        )
        
        if file_path:
            self.scan_path_var.set(file_path)
            self._start_scan()
    
    def _scan_folder_dialog(self):
        """Open folder dialog for scanning a directory."""
        folder_path = filedialog.askdirectory(title="Select folder to scan")
        
        if folder_path:
            self.scan_path_var.set(folder_path)
            self._start_scan()
    
    def _browse_scan_path(self):
        """Browse for scan path."""
        path = filedialog.askdirectory(title="Select path to scan")
        if path:
            self.scan_path_var.set(path)
    
    def _start_scan(self):
        """Start scanning the selected path."""
        scan_path = self.scan_path_var.get().strip()
        
        if not scan_path:
            messagebox.showerror("Error", "Please select a path to scan")
            return
        
        if not Path(scan_path).exists():
            messagebox.showerror("Error", "Selected path does not exist")
            return
        
        # Start scan in background thread
        scan_thread = threading.Thread(target=self._perform_scan, args=(scan_path,), daemon=True)
        scan_thread.start()
        
        # Update UI
        self.progress_var.set(0)
        self.scan_status_var.set("Starting scan...")
        self.status_progress.start()
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
    
    def _perform_scan(self, scan_path: str):
        """Perform the actual scan in a background thread."""
        try:
            if not self.scanner_engine:
                self.update_queue.put({
                    'type': 'scan_progress',
                    'progress': 0,
                    'status': 'Scanner engine not available'
                })
                return
            
            # Update progress
            self.update_queue.put({
                'type': 'scan_progress',
                'progress': 10,
                'status': f'Scanning {scan_path}...'
            })
            
            # Perform scan
            scan_result = self.scanner_engine.scan_path(scan_path)
            
            # Update progress
            self.update_queue.put({
                'type': 'scan_progress',
                'progress': 100,
                'status': f'Scan completed. Found {scan_result.threats_found} threats.'
            })
            
            # Add results
            for detection in scan_result.detections:
                self.update_queue.put({
                    'type': 'scan_result',
                    'result': detection
                })
            
            # Update statistics
            self.stats['scans_performed'] += 1
            self.stats['threats_detected'] += scan_result.threats_found
            
            # Add activity
            self.update_queue.put({
                'type': 'activity',
                'event': 'Scan Completed',
                'details': f'{scan_path} - {scan_result.threats_found} threats found'
            })
            
        except Exception as e:
            self.update_queue.put({
                'type': 'scan_progress',
                'progress': 0,
                'status': f'Scan failed: {e}'
            })
            
            self.update_queue.put({
                'type': 'log_message',
                'message': f'Scan error: {e}',
                'level': 'ERROR'
            })
        
        finally:
            # Stop progress indicator
            self.root.after(100, self.status_progress.stop)
    
    def _add_scan_result(self, detection: Detection):
        """Add a scan result to the results tree."""
        self.results_tree.insert('', 'end', values=(
            detection.file_path,
            detection.threat_name,
            detection.risk_score,
            'Detected'
        ))
    
    def _quick_scan(self):
        """Perform a quick scan of common locations."""
        # Scan Downloads folder
        downloads_path = str(Path.home() / "Downloads")
        if Path(downloads_path).exists():
            self.scan_path_var.set(downloads_path)
            self._start_scan()
    
    def _scan_downloads(self):
        """Scan the Downloads folder."""
        downloads_path = str(Path.home() / "Downloads")
        if Path(downloads_path).exists():
            self.scan_path_var.set(downloads_path)
            self._start_scan()
        else:
            messagebox.showinfo("Info", "Downloads folder not found")
    
    def _scan_desktop(self):
        """Scan the Desktop folder."""
        desktop_path = str(Path.home() / "Desktop")
        if Path(desktop_path).exists():
            self.scan_path_var.set(desktop_path)
            self._start_scan()
        else:
            messagebox.showinfo("Info", "Desktop folder not found")
    
    def _clean_temp_files(self):
        """Clean temporary files (placeholder)."""
        messagebox.showinfo("Info", "Temporary file cleaning is not implemented in this educational version")
    
    def _toggle_realtime_protection(self):
        """Toggle real-time protection on/off."""
        if not self.realtime_manager:
            messagebox.showerror("Error", "Real-time protection manager not available")
            return
        
        if self.realtime_var.get():
            self._start_realtime_protection()
        else:
            self._stop_realtime_protection()
    
    def _start_realtime_protection(self):
        """Start real-time protection."""
        if self.realtime_manager:
            try:
                self.realtime_manager.start_protection()
                self.stats['realtime_active'] = True
                self._add_activity("Real-Time Protection", "Started")
                self._log_message("Real-time protection started", "INFO")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start real-time protection: {e}")
                self._log_message(f"Failed to start real-time protection: {e}", "ERROR")
    
    def _stop_realtime_protection(self):
        """Stop real-time protection."""
        if self.realtime_manager:
            try:
                self.realtime_manager.stop_protection()
                self.stats['realtime_active'] = False
                self._add_activity("Real-Time Protection", "Stopped")
                self._log_message("Real-time protection stopped", "INFO")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to stop real-time protection: {e}")
                self._log_message(f"Failed to stop real-time protection: {e}", "ERROR")
    
    def _show_quarantine_manager(self):
        """Show the quarantine manager window."""
        QuarantineManagerWindow(self.root, self.quarantine_manager)
    
    def _show_settings(self):
        """Show the settings window."""
        SettingsWindow(self.root, self.config)
    
    def _show_about(self):
        """Show the about dialog."""
        about_text = """Educational Antivirus Tool
Version 1.0.0

A comprehensive educational antivirus system for learning
cybersecurity concepts and malware detection techniques.

Features:
• Signature-based detection
• Behavioral analysis
• Heuristic engine
• Machine learning classifier
• Real-time protection
• Quarantine management

This tool is for educational purposes only."""
        
        messagebox.showinfo("About", about_text)
    
    def _show_user_guide(self):
        """Show the user guide window."""
        UserGuideWindow(self.root)
    
    def _add_monitor_path(self):
        """Add a path to monitor."""
        path = filedialog.askdirectory(title="Select path to monitor")
        if path and self.realtime_manager:
            self.realtime_manager.file_monitor.add_watch_path(path)
            self._update_monitor_paths()
    
    def _remove_monitor_path(self):
        """Remove a path from monitoring."""
        selection = self.paths_listbox.curselection()
        if selection and self.realtime_manager:
            path = self.paths_listbox.get(selection[0])
            self.realtime_manager.file_monitor.remove_watch_path(path)
            self._update_monitor_paths()
    
    def _update_monitor_paths(self):
        """Update the monitored paths list."""
        self.paths_listbox.delete(0, tk.END)
        if self.realtime_manager and self.realtime_manager.file_monitor:
            for path in self.realtime_manager.file_monitor.config.watch_paths:
                self.paths_listbox.insert(tk.END, path)
    
    def _add_realtime_event(self, event: Dict[str, Any]):
        """Add a real-time event to the events tree."""
        self.events_tree.insert('', 'end', values=(
            event.get('time', ''),
            event.get('type', ''),
            event.get('file', ''),
            event.get('action', '')
        ))
        
        # Keep only last 100 events
        children = self.events_tree.get_children()
        if len(children) > 100:
            self.events_tree.delete(children[0])
    
    def _add_activity(self, event: str, details: str):
        """Add an activity to the recent activity list."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.activity_tree.insert('', 'end', values=(timestamp, event, details))
        
        # Keep only last 50 activities
        children = self.activity_tree.get_children()
        if len(children) > 50:
            self.activity_tree.delete(children[0])
    
    def _log_message(self, message: str, level: str = "INFO"):
        """Add a message to the log."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}\n"
        
        self.log_text.insert(tk.END, log_entry, level)
        self.log_text.see(tk.END)
        
        # Keep only last 1000 lines
        lines = self.log_text.get("1.0", tk.END).split('\n')
        if len(lines) > 1000:
            self.log_text.delete("1.0", f"{len(lines) - 1000}.0")
    
    def _clear_logs(self):
        """Clear the log display."""
        self.log_text.delete("1.0", tk.END)
    
    def _export_logs(self):
        """Export logs to a file."""
        file_path = filedialog.asksaveasfilename(
            title="Export Logs",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.log_text.get("1.0", tk.END))
                messagebox.showinfo("Success", f"Logs exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {e}")
    
    def _export_report(self):
        """Export scan report."""
        messagebox.showinfo("Info", "Report export feature not implemented in this educational version")
    
    def _show_results_context_menu(self, event):
        """Show context menu for scan results."""
        item = self.results_tree.identify_row(event.y)
        if item:
            self.results_tree.selection_set(item)
            self.results_context_menu.post(event.x_root, event.y_root)
    
    def _quarantine_selected(self):
        """Quarantine selected file."""
        selection = self.results_tree.selection()
        if selection and self.quarantine_manager:
            item = self.results_tree.item(selection[0])
            file_path = item['values'][0]
            
            try:
                # Create a dummy detection for quarantine
                detection = Detection(
                    file_path=file_path,
                    threat_name=item['values'][1],
                    detection_type=DetectionType.SIGNATURE,
                    risk_score=int(item['values'][2]),
                    description="User-initiated quarantine"
                )
                
                result = self.quarantine_manager.quarantine_file(file_path, detection)
                if result:
                    messagebox.showinfo("Success", f"File quarantined: {file_path}")
                    self.stats['files_quarantined'] += 1
                    self._add_activity("File Quarantined", file_path)
                else:
                    messagebox.showerror("Error", f"Failed to quarantine file: {file_path}")
            
            except Exception as e:
                messagebox.showerror("Error", f"Quarantine failed: {e}")
    
    def _ignore_selected(self):
        """Ignore selected detection."""
        selection = self.results_tree.selection()
        if selection:
            self.results_tree.delete(selection[0])
            messagebox.showinfo("Info", "Detection ignored")
    
    def _view_details(self):
        """View details of selected detection."""
        selection = self.results_tree.selection()
        if selection:
            item = self.results_tree.item(selection[0])
            details = f"""Detection Details:

File: {item['values'][0]}
Threat: {item['values'][1]}
Risk Score: {item['values'][2]}
Status: {item['values'][3]}

This is an educational antivirus tool.
Detections may be simulated for learning purposes."""
            
            messagebox.showinfo("Detection Details", details)
    
    def _on_closing(self):
        """Handle window closing."""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            # Stop real-time protection if active
            if self.realtime_manager and self.stats['realtime_active']:
                self.realtime_manager.stop_protection()
            
            self.root.destroy()
    
    def run(self):
        """Run the GUI application."""
        self.is_running = True
        
        # Set up window close handler
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        
        # Initialize monitored paths
        self._update_monitor_paths()
        
        # Start the GUI
        self.root.mainloop()
        
        self.is_running = False


class QuarantineManagerWindow:
    """Quarantine manager window."""
    
    def __init__(self, parent, quarantine_manager):
        """Initialize quarantine manager window."""
        self.quarantine_manager = quarantine_manager
        
        self.window = tk.Toplevel(parent)
        self.window.title("Quarantine Manager")
        self.window.geometry("800x500")
        
        self._create_quarantine_gui()
        self._load_quarantine_data()
    
    def _create_quarantine_gui(self):
        """Create quarantine manager GUI."""
        # Quarantine list
        list_frame = ttk.LabelFrame(self.window, text="Quarantined Files")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.quarantine_tree = ttk.Treeview(list_frame, columns=('File', 'Threat', 'Date', 'Size'), show='headings')
        self.quarantine_tree.heading('File', text='Original File Path')
        self.quarantine_tree.heading('Threat', text='Threat Name')
        self.quarantine_tree.heading('Date', text='Quarantine Date')
        self.quarantine_tree.heading('Size', text='File Size')
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.quarantine_tree.yview)
        self.quarantine_tree.configure(yscrollcommand=scrollbar.set)
        
        self.quarantine_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons
        button_frame = ttk.Frame(self.window)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Restore", command=self._restore_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Delete", command=self._delete_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Refresh", command=self._load_quarantine_data).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Close", command=self.window.destroy).pack(side=tk.RIGHT, padx=2)
    
    def _load_quarantine_data(self):
        """Load quarantine data."""
        # Clear existing items
        for item in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(item)
        
        if not self.quarantine_manager:
            return
        
        # Load quarantined files (placeholder)
        # In a real implementation, this would load from quarantine database
        sample_entries = [
            ("C:\\Users\\User\\Downloads\\suspicious.exe", "Trojan.Generic", "2024-01-15 10:30:00", "1.2 MB"),
            ("C:\\Temp\\malware.dll", "Backdoor.Agent", "2024-01-14 15:45:00", "856 KB")
        ]
        
        for entry in sample_entries:
            self.quarantine_tree.insert('', 'end', values=entry)
    
    def _restore_file(self):
        """Restore selected file from quarantine."""
        selection = self.quarantine_tree.selection()
        if selection:
            item = self.quarantine_tree.item(selection[0])
            file_path = item['values'][0]
            
            if messagebox.askyesno("Confirm Restore", f"Restore file to original location?\n\n{file_path}"):
                # Placeholder for restore functionality
                messagebox.showinfo("Info", "File restore functionality not implemented in educational version")
    
    def _delete_file(self):
        """Delete selected file from quarantine."""
        selection = self.quarantine_tree.selection()
        if selection:
            item = self.quarantine_tree.item(selection[0])
            file_path = item['values'][0]
            
            if messagebox.askyesno("Confirm Delete", f"Permanently delete quarantined file?\n\n{file_path}"):
                self.quarantine_tree.delete(selection[0])
                messagebox.showinfo("Info", "File deleted from quarantine")


class SettingsWindow:
    """Settings configuration window."""
    
    def __init__(self, parent, config):
        """Initialize settings window."""
        self.config = config
        
        self.window = tk.Toplevel(parent)
        self.window.title("Settings")
        self.window.geometry("600x400")
        
        self._create_settings_gui()
        self._load_settings()
    
    def _create_settings_gui(self):
        """Create settings GUI."""
        notebook = ttk.Notebook(self.window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # General settings
        general_frame = ttk.Frame(notebook)
        notebook.add(general_frame, text="General")
        
        # Detection settings
        detection_frame = ttk.Frame(notebook)
        notebook.add(detection_frame, text="Detection")
        
        # Real-time settings
        realtime_frame = ttk.Frame(notebook)
        notebook.add(realtime_frame, text="Real-Time")
        
        # Buttons
        button_frame = ttk.Frame(self.window)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Save", command=self._save_settings).pack(side=tk.RIGHT, padx=2)
        ttk.Button(button_frame, text="Cancel", command=self.window.destroy).pack(side=tk.RIGHT, padx=2)
        ttk.Button(button_frame, text="Reset to Defaults", command=self._reset_settings).pack(side=tk.LEFT, padx=2)
    
    def _load_settings(self):
        """Load current settings."""
        # Placeholder for settings loading
        pass
    
    def _save_settings(self):
        """Save settings."""
        messagebox.showinfo("Info", "Settings saved successfully")
        self.window.destroy()
    
    def _reset_settings(self):
        """Reset settings to defaults."""
        if messagebox.askyesno("Confirm Reset", "Reset all settings to defaults?"):
            messagebox.showinfo("Info", "Settings reset to defaults")


class UserGuideWindow:
    """User guide window."""
    
    def __init__(self, parent):
        """Initialize user guide window."""
        self.window = tk.Toplevel(parent)
        self.window.title("User Guide")
        self.window.geometry("700x500")
        
        self._create_guide_gui()
    
    def _create_guide_gui(self):
        """Create user guide GUI."""
        guide_text = scrolledtext.ScrolledText(self.window, wrap=tk.WORD)
        guide_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        guide_content = """Educational Antivirus Tool - User Guide

OVERVIEW
This educational antivirus tool demonstrates various malware detection
techniques and cybersecurity concepts for learning purposes.

MAIN FEATURES

1. DASHBOARD
   • View system statistics and recent activity
   • Quick access to common scanning operations
   • Real-time protection status monitoring

2. SCANNING
   • File and folder scanning capabilities
   • Multiple detection engines (signature, behavioral, heuristic, ML)
   • Detailed scan results with threat information

3. REAL-TIME PROTECTION
   • Continuous file system monitoring
   • Automatic threat detection and quarantine
   • Configurable monitoring paths and exclusions

4. QUARANTINE MANAGEMENT
   • Secure isolation of detected threats
   • File restoration and permanent deletion options
   • Quarantine history and metadata

GETTING STARTED

1. Start by running a quick scan of your Downloads folder
2. Enable real-time protection for continuous monitoring
3. Review scan results and quarantine any detected threats
4. Check the logs for detailed information about system activity

EDUCATIONAL NOTES

This tool is designed for educational purposes and includes:
• Simulated threat detection for learning
• Safe test samples (EICAR) for testing
• Detailed explanations of detection methods
• No actual malware handling capabilities

For questions or support, refer to the documentation or
contact your instructor.
"""
        
        guide_text.insert("1.0", guide_content)
        guide_text.config(state=tk.DISABLED)


def create_dashboard(config=None, scanner_engine=None, quarantine_manager=None, realtime_manager=None):
    """Create and return a dashboard instance."""
    return AntivirusDashboard(config, scanner_engine, quarantine_manager, realtime_manager)


if __name__ == "__main__":
    # Test the dashboard
    print("🖥️ Testing Antivirus Dashboard")
    
    dashboard = create_dashboard()
    dashboard.run()