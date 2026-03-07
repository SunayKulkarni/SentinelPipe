import os
import requests
import logging

logger = logging.getLogger(__name__)

# Get the directory where this script is located
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
database_location = os.path.join(_SCRIPT_DIR, "..", "media", "talos.txt")

def talos(query: str):
    """Check if an IP is blacklisted in the Talos database."""
    try:
        result = {"blacklisted": False}
        
        if not os.path.isfile(database_location):
            logger.info("Talos database not found, downloading...")
            if not update():
                return {"blacklisted": False, "error": "Failed to download Talos database"}

        with open(database_location, "r", encoding="utf-8") as f:
            db = f.read()

        db_list = [ip.strip() for ip in db.split("\n") if ip.strip()]
        if query in db_list:
            result["blacklisted"] = True

        return result
    except Exception as e:
        logger.error(f"Error checking Talos database: {e}")
        return {"blacklisted": False, "error": str(e)}

def update():
    """Download the latest Talos IP blocklist."""
    try:
        logger.info("Starting download of Talos database")
        url = "https://snort.org/downloads/ip-block-list"
        r = requests.get(url, timeout=30)
        r.raise_for_status()

        # Ensure the directory exists
        os.makedirs(os.path.dirname(database_location), exist_ok=True)

        with open(database_location, "w", encoding="utf-8") as f:
            f.write(r.content.decode())

        logger.info("Finished downloading Talos database")
        return True
    except Exception as e:
        logger.error(f"Failed to update Talos database: {e}")
        return False


if __name__ == "__main__":
    # Configure logging for standalone testing
    logging.basicConfig(level=logging.INFO)
    print(talos("109.196.187.208"))