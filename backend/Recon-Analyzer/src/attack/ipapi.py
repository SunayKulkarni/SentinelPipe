import logging
import os

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

api_key = os.getenv("ipAPI_KEY")
batch_url = "http://ip-api.com/batch"
dns_url = "http://edns.ip-api.com/json"


def ipapi(ip_addr):
    """Get IP geolocation and DNS information."""
    try:
        logger.info(f"Fetching IP info for {ip_addr}")
        
        IP = [
            {
                "query": ip_addr,
                "fields": "status,message,country,countryCode,region,regionName,city,zip,timezone,isp,org,as",
                "lang": "us",
            }
        ]

        response_batch = requests.post(batch_url, json=IP, timeout=10)
        response_batch.raise_for_status()

        response_dns = requests.get(dns_url, timeout=10)
        response_dns.raise_for_status()

        response = {
            "ip_info": response_batch.json(),
            "dns_info": response_dns.json()
        }

        logger.info(f"IP info retrieved successfully for {ip_addr}")
        return response
    except requests.exceptions.Timeout:
        logger.error(f"Timeout fetching IP info for {ip_addr}")
        return {"error": "Request timed out"}
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error for {ip_addr}: {e}")
        return {"error": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error for {ip_addr}: {e}")
        return {"error": str(e)}


if __name__ == "__main__":
    # Configure logging for standalone testing
    logging.basicConfig(level=logging.INFO)
    print(ipapi("198.98.51.189"))