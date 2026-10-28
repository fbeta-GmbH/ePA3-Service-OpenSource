import os 
import time
import tempfile

from epa_core.runtime_config.constants import Config

class Builder_Locker():
    """This class provides a simple file-based locking mechanism to prevent concurrent execution of the certificate builder process."""

    def __init__(self, lock_file: str):
        self.lock_file = os.path.join(tempfile.gettempdir(), f"{lock_file}.lock")

    def lock_for_builder(self, timeout = 300) -> bool:
        """Creates a lock file to indicate that the builder process is running. If the lock file already exists, it waits until the lock is released or a timeout occurs.

        Args:
            timeout (int): The maximum time to wait for the lock to be released, in seconds.
        """
        
        start_time = time.time()
        while True:
            try:
                # Attempt to create the lock file atomically
                fd = os.open(self.lock_file, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                os.close(fd)
                Config.logger.info(f"Acquire builder lock: {os.getpid()} - {self.lock_file}")
                return True
            
            except FileExistsError:
                Config.logger.info(f"Builder lock already exists:  {os.getpid()} - {self.lock_file}. Waiting for lock to be released.")
                while os.path.exists(self.lock_file):
                    time.sleep(1)
                    
                    if time.time() - start_time > timeout:
                        raise TimeoutError("Timeout while waiting for builder lock to be released.")
                
                return False

            
    def unlock_for_builder(self) -> bool:
        """Removes the lock file to indicate that the builder process has finished.

        Returns:
            bool: True if the lock file was successfully removed, False if the lock file was not found.
        """
        try:
            os.remove(self.lock_file)
            return True
        except FileNotFoundError:
            Config.logger.debug(f"Builder lock file already removed: {self.lock_file}")
            return False
        except PermissionError:
            Config.logger.warning(f"Builder lock file is currently in use and could not be removed: {self.lock_file}")
            return False
            
                
                