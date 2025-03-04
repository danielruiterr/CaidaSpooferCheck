#!/usr/bin/env python3
"""
CAIDA Spoofer Data Collection Tool

This script retrieves IPv4 clients from the CAIDA Spoofer Data API for the past year
and generates two separate files with formatted data for clients that can spoof routed
and private addresses.

Features:
- Formatted output with session URLs and key information
- Real-time ETA calculation based on processing speed
- Cumulative statistics display
- Robust error handling and performance optimizations
"""

import json
import requests
from datetime import datetime, timedelta
import argparse
import os
import time
from typing import Dict, List, Optional, Tuple, TextIO
import sys


class SpooferCollector:
    """Class to handle collection and processing of spoofer data"""
    
    def __init__(self, start_date: str, routed_output: str, private_output: str, 
                 api_base: str = "https://api.spoofer.caida.org"):
        """
        Initialize the spoofer collector.
        
        Args:
            start_date: The start date in ISO format (YYYY-MM-DD)
            routed_output: Path to the output file for routed spoofing
            private_output: Path to the output file for private spoofing
            api_base: Base URL for the CAIDA Spoofer API
        """
        self.start_date = start_date
        self.routed_output = routed_output
        self.private_output = private_output
        self.api_base = api_base
        self.headers = {"Accept": "application/ld+json"}
        
        # Statistics tracking
        self.total_records = 0
        self.total_routed = 0
        self.total_private = 0
        self.page = 1
        self.start_time = time.time()
        self.pages_processed = 0
        self.estimated_total_pages = None
        
    def fetch_page(self, url: str) -> Optional[Dict]:
        """
        Fetch a page of data from the API with retry logic.
        
        Args:
            url: Full URL to fetch
            
        Returns:
            JSON response data or None if request failed after retries
        """
        max_retries = 3
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=self.headers, timeout=30)
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    print(f"Error fetching data: {e}. Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    print(f"Failed to fetch data after {max_retries} attempts: {e}")
                    return None
    
    def format_record(self, session: Dict) -> str:
        """
        Format a session record according to the specified format.
        
        Args:
            session: The session data dictionary
            
        Returns:
            Formatted string representation of the session
        """
        session_id = session.get("session")
        asn4 = session.get("asn4", "N/A")
        client4 = session.get("client4", "N/A")
        country = session.get("country", "N/A")
        privatespoof = session.get("privatespoof", "N/A")
        routedspoof = session.get("routedspoof", "N/A")
        timestamp = session.get("timestamp", "N/A")
        
        formatted = (
            f"Session: https://spoofer.caida.org/report.php?sessionid={session_id}, "
            f"ASN4 number: {asn4}, "
            f"Client4: {client4}, "
            f"Country: {country}, "
            f"Privatespoof: {privatespoof}, "
            f"Routedspoof: {routedspoof}, "
            f"Timestamp: {timestamp}"
        )
        
        return formatted
    
    def process_data(self, data: Dict, routed_file: TextIO, private_file: TextIO) -> Tuple[int, int]:
        """
        Process a page of data and write matching records to appropriate files.
        
        Args:
            data: JSON response data
            routed_file: File handle for routed spoof records
            private_file: File handle for private spoof records
            
        Returns:
            Tuple of (routed_count, private_count) for this page
        """
        routed_count = 0
        private_count = 0
        
        for session in data.get("hydra:member", []):
            if session.get("client4"):  # Only process IPv4 clients
                
                # Check for routed spoofing
                if session.get("routedspoof") == "received":
                    routed_file.write(self.format_record(session) + "\n")
                    routed_count += 1
                    
                # Check for private spoofing
                if session.get("privatespoof") == "received":
                    private_file.write(self.format_record(session) + "\n")
                    private_count += 1
                    
        return routed_count, private_count
    
    def estimate_completion(self) -> str:
        """
        Calculate and return the estimated time to completion.
        
        Returns:
            String representation of the ETA
        """
        if self.pages_processed < 2:
            return "Calculating..."
        
        elapsed_time = time.time() - self.start_time
        avg_time_per_page = elapsed_time / self.pages_processed
        
        # If we have an estimate of total pages, use it
        if self.estimated_total_pages:
            remaining_pages = self.estimated_total_pages - self.pages_processed
            estimated_seconds_left = remaining_pages * avg_time_per_page
            
            # Format the ETA
            if estimated_seconds_left < 60:
                return f"{int(estimated_seconds_left)} seconds"
            elif estimated_seconds_left < 3600:
                return f"{int(estimated_seconds_left / 60)} minutes"
            else:
                hours = int(estimated_seconds_left / 3600)
                minutes = int((estimated_seconds_left % 3600) / 60)
                return f"{hours} hours, {minutes} minutes"
        else:
            # If we don't have a total page estimate, just show processing rate
            return f"Processing {1/avg_time_per_page:.2f} pages/second"
            
    def update_progress(self, data: Dict) -> None:
        """
        Update progress information and estimate total pages if possible.
        
        Args:
            data: The JSON response data
        """
        self.pages_processed += 1
        
        # Try to estimate total pages from hydra:view if available
        if not self.estimated_total_pages and "hydra:view" in data:
            view = data["hydra:view"]
            if "hydra:last" in view:
                last_url = view["hydra:last"]
                # Extract page number from URL
                try:
                    page_param = [p for p in last_url.split("&") if p.startswith("page=")]
                    if page_param:
                        self.estimated_total_pages = int(page_param[0].split("=")[1])
                        print(f"Estimated total pages: {self.estimated_total_pages}")
                except (ValueError, IndexError):
                    pass
    
    def display_progress(self) -> None:
        """Display progress information including ETA and cumulative statistics."""
        eta = self.estimate_completion()
        
        # Clear the current line and display updated progress
        sys.stdout.write("\r\033[K")  # Clear line
        sys.stdout.write(
            f"Page {self.page} | "
            f"Total routed spoofers: {self.total_routed} | "
            f"Total private spoofers: {self.total_private} | "
            f"ETA: {eta}"
        )
        sys.stdout.flush()
    
    def collect_data(self) -> None:
        """Fetch spoofer data from CAIDA API and save to separate files."""
        next_url = f"/sessions?timestamp[after]={self.start_date}"
        
        print(f"Starting data collection from {self.start_date} to present...")
        
        # Open both output files
        with open(self.routed_output, 'w') as routed_file, open(self.private_output, 'w') as private_file:
            # Write headers for the files
            file_header = (
                f"# IPv4 clients that can spoof - Data from CAIDA Spoofer API\n"
                f"# Collection date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"# Data period: {self.start_date} to present\n"
                f"# Format: Formatted text\n\n"
            )
            
            routed_file.write(file_header)
            private_file.write(file_header)
            
            # Loop through all pages
            while next_url:
                # Make the API request
                data = self.fetch_page(f"{self.api_base}{next_url}")
                
                if not data:
                    print("\nFailed to fetch data. Stopping.")
                    break
                
                # Update progress tracking
                self.update_progress(data)
                
                # Process the data
                routed_count, private_count = self.process_data(data, routed_file, private_file)
                
                # Update counters
                self.total_records += len(data.get("hydra:member", []))
                self.total_routed += routed_count
                self.total_private += private_count
                
                # Display progress
                self.display_progress()
                
                # Check if there is a next page
                if "hydra:view" in data and "hydra:next" in data["hydra:view"]:
                    next_url = data["hydra:view"]["hydra:next"]
                    self.page += 1
                else:
                    next_url = None
        
        # Print final summary
        elapsed_time = time.time() - self.start_time
        print("\n\nData collection complete.")
        print(f"Total records processed: {self.total_records}")
        print(f"IPv4 clients that can spoof routed addresses: {self.total_routed}")
        print(f"IPv4 clients that can spoof private addresses: {self.total_private}")
        print(f"Results saved to: {self.routed_output} and {self.private_output}")
        print(f"Total time: {timedelta(seconds=int(elapsed_time))}")


def main():
    """Parse arguments and run the data collection."""
    parser = argparse.ArgumentParser(
        description="Collect IPv4 spoofer data from CAIDA API",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--routed-output", 
        default="ipv4_routed_spoofers.txt", 
        help="Output file path for routed spoofing clients"
    )
    parser.add_argument(
        "--private-output", 
        default="ipv4_private_spoofers.txt", 
        help="Output file path for private spoofing clients"
    )
    parser.add_argument(
        "--days", 
        type=int, 
        default=365, 
        help="Number of days to look back"
    )
    parser.add_argument(
        "--api-base",
        default="https://api.spoofer.caida.org",
        help="Base URL for the CAIDA Spoofer API"
    )
    
    args = parser.parse_args()
    
    # Calculate the start date
    start_date = (datetime.now() - timedelta(days=args.days)).strftime("%Y-%m-%d")
    
    # Ensure output directories exist
    for output_file in [args.routed_output, args.private_output]:
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    # Create and run the collector
    collector = SpooferCollector(
        start_date, 
        args.routed_output, 
        args.private_output,
        args.api_base
    )
    collector.collect_data()


if __name__ == "__main__":
    main()
