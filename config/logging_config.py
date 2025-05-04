import logging
import logging.handlers
import threading
import time
import os
from logging.handlers import BaseRotatingHandler
import io
import sys

# Global variables to control singleton behavior
_udf_logger = None
_udf_logger_lock = threading.Lock()
_directory_checked = False

class HighPerformanceFileHandler(BaseRotatingHandler):
    """
    Ultra high-performance file handler that uses buffering and direct writes.
    Creates multiple batch files when size limits are reached.
    """
    def __init__(self, basename, mode='a', max_lines=1000000, backup_count=10, buffer_size=10000):
        # Add alert counter
        self.alert_counter = 0
        self.last_alert_id = None
        self.debug_interval = 10000  # Print debug every 10k lines
        
        # Ensure base directory exists first
        basedir = os.path.dirname(basename)
        if basedir and not os.path.exists(basedir):
            try:
                os.makedirs(basedir)
                print(f"Created log directory: {basedir}")
            except Exception as e:
                print(f"Error creating directory {basedir}: {e}")
                
        self.basename = basename
        self.mode = mode
        self.max_lines = max_lines
        self.backup_count = backup_count
        self.buffer_size = buffer_size
        self.line_count = 0
        self.current_batch = 1
        self.buffer = []
        self.last_flush_time = time.time()
        
        # Find the next available batch number
        while os.path.exists(self._get_batch_filename(self.current_batch)):
            self.current_batch += 1
            
        print(f"Starting with log batch file #{self.current_batch}")
        
        # Initialize with proper filename
        filename = self._get_batch_filename(self.current_batch)
        BaseRotatingHandler.__init__(self, filename, mode)
        
        # Start a background flush thread
        self._stop_thread = False
        self._thread = threading.Thread(target=self._background_flush)
        self._thread.daemon = True
        self._thread.start()

    def _get_batch_filename(self, batch_number):
        """Generate a filename for the given batch number."""
        dirname = os.path.dirname(self.basename)
        basename_only = os.path.basename(self.basename)
        
        # Split basename into name and extension
        name, ext = os.path.splitext(basename_only)
        if not ext:
            ext = '.log'
            
        # Create batch filename
        batch_name = f"{name}_batch_{batch_number}{ext}"
        
        # Join with directory if any
        if dirname:
            return os.path.join(dirname, batch_name)
        else:
            return batch_name

    def emit(self, record):
        """Buffer log record and check for rotation with improved debugging."""
        try:
            msg = self.format(record)
            
            # Track alerts - check if this is a new alert ID
            try:
                # Extract alert ID from message if possible
                if "|User:" in msg and "[Alert:" in msg:
                    alert_id_str = msg.split("[Alert:")[1].split("|")[0].strip()
                    current_alert_id = int(alert_id_str)
                    
                    if self.last_alert_id != current_alert_id:
                        self.alert_counter += 1
                        self.last_alert_id = current_alert_id
            except:
                pass  # Ignore errors in alert tracking
                
            # Add to buffer instead of writing directly
            with _udf_logger_lock:  # Protect buffer access
                self.buffer.append(msg + self.terminator)
                self.line_count += 1
                
                # Print debug info periodically
                if self.line_count % self.debug_interval == 0:
                    print(f"DEBUG: {self.baseFilename} has {self.line_count}/{self.max_lines} lines ({self.alert_counter} alerts)")
                
                # Check for rotation
                if self.line_count >= self.max_lines:
                    print(f"ROTATION NEEDED: {self.baseFilename} has reached {self.line_count} lines!")
                    self._flush_and_rotate()
                    
                # Force flush if buffer is getting large
                if len(self.buffer) >= self.buffer_size:
                    self._flush_buffer()
                    
        except Exception as e:
            print(f"ERROR in emit: {str(e)}")
            self.handleError(record)

    def _flush_buffer(self):
        """Flush the buffer to disk with debugging."""
        if not self.buffer:
            return
            
        try:
            buffer_size = len(self.buffer)
            print(f"Flushing {buffer_size} log lines to {self.baseFilename}")
            
            # Use direct binary write for speed
            if hasattr(self.stream, 'buffer'):
                self.stream.buffer.write(''.join(self.buffer).encode('utf-8'))
            else:
                self.stream.write(''.join(self.buffer))
            
            self.stream.flush()
            self.buffer = []
            self.last_flush_time = time.time()
            
            print(f"Flush complete. File now has approx {self.line_count} lines")
            
            # Check file size to verify
            try:
                file_size = os.path.getsize(self.baseFilename)
                print(f"File size: {file_size/1024/1024:.2f} MB")
            except:
                pass
                
        except Exception as e:
            print(f"ERROR flushing log buffer: {str(e)}")
            # Try to recover
            try:
                if not self.stream or self.stream.closed:
                    print(f"Reopening {self.baseFilename} after error")
                    self.stream = open(self.baseFilename, self.mode)
            except:
                pass

    def _flush_and_rotate(self):
        """Flush buffer and rotate to a new file with detailed debugging."""
        print(f"ROTATING: {self.baseFilename} at {self.line_count} lines with {self.alert_counter} alerts")
        
        try:
            # First flush any pending logs
            self._flush_buffer()
            
            # Close current file
            if self.stream:
                self.stream.close()
                self.stream = None
            
            # Verify the file actually exists and has content
            if os.path.exists(self.baseFilename):
                size_mb = os.path.getsize(self.baseFilename) / 1024 / 1024
                print(f"Completed file {self.baseFilename} size: {size_mb:.2f} MB")
                
                # Count lines in file to verify
                try:
                    with open(self.baseFilename, 'r', errors='ignore') as f:
                        actual_lines = sum(1 for _ in f)
                    print(f"VERIFICATION: File contains {actual_lines} actual lines (tracked: {self.line_count})")
                except Exception as e:
                    print(f"Error verifying line count: {e}")
            else:
                print(f"WARNING: Expected file {self.baseFilename} doesn't exist!")
            
            # Move to the next batch
            self.current_batch += 1
            print(f"Creating new log batch file #{self.current_batch}")
            
            # Remove old log files if we exceed the backup count
            if self.backup_count > 0:
                old_batch = self.current_batch - self.backup_count
                if old_batch > 0:
                    old_file = self._get_batch_filename(old_batch)
                    if os.path.exists(old_file):
                        try:
                            os.remove(old_file)
                            print(f"Removed old log file: {old_file}")
                        except Exception as e:
                            print(f"Failed to remove old log file: {old_file} - {str(e)}")
            
            # Set up the new file
            self.baseFilename = self._get_batch_filename(self.current_batch)
            self.line_count = 0
            self.alert_counter = 0  # Reset alert counter for new file
            
            print(f"Now writing to: {self.baseFilename}")
            
            # Open with large buffer
            if self.encoding:
                self.stream = open(self.baseFilename, self.mode, encoding=self.encoding, buffering=io.DEFAULT_BUFFER_SIZE)
            else:
                self.stream = open(self.baseFilename, self.mode, buffering=io.DEFAULT_BUFFER_SIZE)
                
            # Write a header to the new file
            try:
                header = f"# Log file {self.current_batch} started at {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                self.stream.write(header)
                self.stream.flush()
                self.line_count += 1
            except Exception as e:
                print(f"Error writing header: {str(e)}")
                
        except Exception as e:
            print(f"ERROR during log rotation: {str(e)}")
            import traceback
            print(traceback.format_exc())
            # Try to recover by reopening the current file
            try:
                if not self.stream:
                    self.stream = open(self.baseFilename, self.mode)
                    print(f"Reopened file {self.baseFilename} after error")
            except Exception as e:
                print(f"Failed to recover from rotation error: {str(e)}")

    def _background_flush(self):
        """Background thread to periodically flush logs."""
        while not self._stop_thread:
            time.sleep(1.0)  # Check every second
            
            with _udf_logger_lock:
                # Flush if there's data and it's been a while
                if self.buffer and time.time() - self.last_flush_time > 2.0:
                    self._flush_buffer()
    
    def close(self):
        """Clean up resources."""
        self._stop_thread = True
        if self._thread.is_alive():
            self._thread.join(timeout=2.0)
            
        with _udf_logger_lock:
            self._flush_buffer()
            
        if self.stream:
            self.stream.close()
            self.stream = None
        
        BaseRotatingHandler.close(self)


def setup_udf_logger(minimal=False, max_lines_per_file=1000000):
    """
    Create a high-performance logger that writes to multiple batch files.
    Uses a singleton pattern for efficiency.
    """
    global _udf_logger, _directory_checked
    
    # Return existing logger if possible
    if _udf_logger is not None:
        return _udf_logger
    
    # Thread-safe initialization
    with _udf_logger_lock:
        if _udf_logger is not None:
            return _udf_logger
        
        # Only check directory once
        if not _directory_checked:
            try:
                os.makedirs("logs", exist_ok=True)
                _directory_checked = True
                print(f"Ensured logs directory exists at {time.time()}")
            except Exception as e:
                print(f"Warning: Could not create logs directory: {e}")
        
        # Create a new logger
        udf_logger = logging.getLogger("alert_analysis_udf")
        
        # Clear any existing handlers
        if udf_logger.handlers:
            for handler in udf_logger.handlers:
                udf_logger.removeHandler(handler)
        
        # Set appropriate level
        log_level = logging.WARNING if minimal else logging.INFO
        udf_logger.setLevel(log_level)
        
        try:
            # Create high-performance file handler
            file_handler = HighPerformanceFileHandler(
                "logs/alert_analysis_detailed.log",
                max_lines=max_lines_per_file,
                backup_count=50,
                buffer_size=50000  # Large buffer for better performance
            )
            file_handler.setLevel(log_level)
            
            # Formatter
            formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s"
            )
            file_handler.setFormatter(formatter)
            
            # Add to logger
            udf_logger.addHandler(file_handler)
            print(f"Created high-performance logger with {max_lines_per_file} lines per file")
            
        except Exception as e:
            print(f"Warning: Error setting up UDF logger: {e}")
            udf_logger.addHandler(logging.NullHandler())
        
        # Store in global variable
        _udf_logger = udf_logger
        return udf_logger


def setup_logging(log_file: str = "alert_analysis.log", log_level: int = logging.INFO) -> logging.Logger:
    """
    Set up the main application logger.
    """
    # Create logger
    logger = logging.getLogger("alert_analysis")
    logger.setLevel(log_level)
    logger.handlers = []  # Clear any existing handlers
    
    # Create file handler with large buffer
    try:
        # Ensure directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        # Create buffered handler
        file_handler = logging.FileHandler(log_file, 'a')
        file_handler.setLevel(log_level)
        
        # Formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s"
        )
        file_handler.setFormatter(formatter)
        
        # Add to logger
        logger.addHandler(file_handler)
        
    except Exception as e:
        print(f"Error setting up main logger: {e}")
        # Fall back to stderr
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(log_level)
        logger.addHandler(handler)
    
    return logger


def check_log_files():
    """Check and report on log files currently in the system."""
    try:
        import glob
        log_files = glob.glob("logs/alert_analysis_detailed_batch_*.log")
        
        print(f"\n{'='*50}")
        print(f"LOG FILE STATUS CHECK - {len(log_files)} batch files found")
        print(f"{'='*50}")
        
        total_size = 0
        total_lines = 0
        
        for log_file in sorted(log_files):
            try:
                size = os.path.getsize(log_file)
                size_mb = size / 1024 / 1024
                total_size += size
                
                # Count lines
                with open(log_file, 'r', errors='ignore') as f:
                    line_count = sum(1 for _ in f)
                total_lines += line_count
                
                # Count alerts (approximate)
                alert_count = 0
                last_alert_id = None
                with open(log_file, 'r', errors='ignore') as f:
                    for line in f:
                        if "|User:" in line and "[Alert:" in line:
                            try:
                                alert_id_str = line.split("[Alert:")[1].split("|")[0].strip()
                                current_alert_id = int(alert_id_str)
                                
                                if last_alert_id != current_alert_id:
                                    alert_count += 1
                                    last_alert_id = current_alert_id
                            except:
                                pass
                
                print(f"File: {log_file}")
                print(f"  - Size: {size_mb:.2f} MB")
                print(f"  - Lines: {line_count}")
                print(f"  - Alerts: ~{alert_count}")
                print(f"  - Lines/Alert: ~{line_count/alert_count if alert_count else 0:.1f}")
                print(f"  - Last Modified: {time.ctime(os.path.getmtime(log_file))}")
                print()
                
            except Exception as e:
                print(f"Error checking {log_file}: {str(e)}")
                
        print(f"{'='*50}")
        print(f"Total size: {total_size/1024/1024:.2f} MB")
        print(f"Total lines: {total_lines}")
        print(f"{'='*50}\n")
        
    except Exception as e:
        print(f"Error in check_log_files: {str(e)}")


# Initialize global logger
logger = setup_logging()

# Configure PySpark logging to be quiet
pyspark_logger = logging.getLogger('py4j')
pyspark_logger.setLevel(logging.ERROR)