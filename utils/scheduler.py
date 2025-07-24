import threading
import time
import logging
from datetime import datetime


class TokenCleanupScheduler:
    """Background scheduler for token cleanup tasks."""
    
    def __init__(self, token_manager, interval_hours=24):
        self.token_manager = token_manager
        self.interval_hours = interval_hours
        self.running = False
        self.thread = None
        self.logger = logging.getLogger(__name__)
    
    def start(self):
        """Start the cleanup scheduler."""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._cleanup_loop, daemon=True)
            self.thread.start()
            self.logger.info(f"Token cleanup scheduler started (interval: {self.interval_hours}h)")
    
    def stop(self):
        """Stop the cleanup scheduler."""
        self.running = False
        if self.thread:
            self.thread.join()
            self.logger.info("Token cleanup scheduler stopped")
    
    def _cleanup_loop(self):
        """Main cleanup loop that runs in background."""
        while self.running:
            try:
                self.logger.info("Running token cleanup...")
                cleaned_count = self.token_manager.cleanup_expired_tokens()
                
                if cleaned_count > 0:
                    self.logger.info(f"Cleaned up {cleaned_count} expired tokens")
                
                # Get token statistics
                stats = self.token_manager.get_token_stats()
                self.logger.info(f"Token stats - Active: {stats['active']}, Inactive: {stats['inactive']}, Total: {stats['total']}")
                
            except Exception as e:
                self.logger.error(f"Token cleanup error: {e}")
            
            # Sleep for the specified interval (convert hours to seconds)
            time.sleep(self.interval_hours * 3600)
    
    def run_cleanup_now(self):
        """Run cleanup immediately (useful for manual triggers)."""
        try:
            cleaned_count = self.token_manager.cleanup_expired_tokens()
            self.logger.info(f"Manual cleanup completed - removed {cleaned_count} tokens")
            return cleaned_count
        except Exception as e:
            self.logger.error(f"Manual cleanup error: {e}")
            return 0