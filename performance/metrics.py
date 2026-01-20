"""
Performance Metrics Module for ZKP Capstone Project
====================================================
This module handles timing measurements and CSV logging for all ZKP operations.
Used by both authentication and forensics modules.
"""

import time
import csv
import os
from datetime import datetime


class PerformanceTracker:
    """
    Tracks and records performance metrics for ZKP operations.
    Measures proof generation time and verification time.
    Stores results in CSV format for analysis.
    """
    
    def __init__(self):
        # Get the project root directory (parent of performance folder)
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.csv_file = os.path.join(self.base_dir, "results.csv")
        self.start_time = None
        self.end_time = None
        
        # Initialize CSV file with headers if it does not exist or is empty
        self._initialize_csv()
    
    def _initialize_csv(self):
        """
        Create CSV file with headers if it does not exist or is empty.
        Headers: timestamp, use_case, operation, time_seconds, status
        """
        needs_header = False
        
        if not os.path.exists(self.csv_file):
            needs_header = True
        else:
            # Check if file is empty or only has whitespace
            try:
                with open(self.csv_file, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    if not content or content == "timestamp,use_case,operation,time_seconds,status":
                        needs_header = True
            except:
                needs_header = True
        
        if needs_header:
            with open(self.csv_file, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow([
                    "timestamp",
                    "use_case",
                    "operation",
                    "time_seconds",
                    "status"
                ])
    
    def start_timer(self):
        """
        Start the performance timer.
        Uses time.perf_counter() for high precision measurement.
        """
        self.start_time = time.perf_counter()
    
    def stop_timer(self):
        """
        Stop the performance timer and return elapsed time.
        Returns time in seconds with high precision.
        """
        self.end_time = time.perf_counter()
        elapsed = self.end_time - self.start_time
        return elapsed
    
    def measure_operation(self, operation_func, *args, **kwargs):
        """
        Measure the execution time of any operation.
        
        Parameters:
            operation_func: The function to measure
            *args, **kwargs: Arguments to pass to the function
        
        Returns:
            tuple: (result of function, elapsed time in seconds)
        """
        self.start_timer()
        result = operation_func(*args, **kwargs)
        elapsed = self.stop_timer()
        return result, elapsed
    
    def log_result(self, use_case, operation, time_seconds, status):
        """
        Log a performance result to the CSV file.
        
        Parameters:
            use_case: String identifying the use case (authentication/forensics)
            operation: String identifying the operation (proof_generation/verification)
            time_seconds: Float representing elapsed time
            status: String indicating result (VERIFIED/REJECTED/ERROR)
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(self.csv_file, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow([
                timestamp,
                use_case,
                operation,
                f"{time_seconds:.6f}",
                status
            ])
    
    def format_time(self, seconds):
        """
        Format time in a human-readable way.
        
        Parameters:
            seconds: Float representing time in seconds
        
        Returns:
            String with formatted time
        """
        if seconds < 0.001:
            return f"{seconds * 1000000:.2f} microseconds"
        elif seconds < 1:
            return f"{seconds * 1000:.2f} milliseconds"
        else:
            return f"{seconds:.4f} seconds"
    
    def print_metrics(self, use_case, proof_time, verify_time, status):
        """
        Print performance metrics to terminal in a clean format.
        
        Parameters:
            use_case: String identifying the use case
            proof_time: Float representing proof generation time
            verify_time: Float representing verification time
            status: String indicating verification result
        """
        print("\n" + "=" * 50)
        print("PERFORMANCE METRICS")
        print("=" * 50)
        print(f"Use Case        : {use_case}")
        print(f"Proof Time      : {self.format_time(proof_time)}")
        print(f"Verify Time     : {self.format_time(verify_time)}")
        print(f"Total Time      : {self.format_time(proof_time + verify_time)}")
        print(f"Status          : {status}")
        print("=" * 50 + "\n")


# Global instance for easy access across modules
tracker = PerformanceTracker()


def get_tracker():
    """
    Get the global PerformanceTracker instance.
    This ensures all modules use the same tracker.
    """
    return tracker