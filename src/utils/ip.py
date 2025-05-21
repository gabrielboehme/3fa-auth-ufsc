import ipinfo
import socket
import os


class IPUtils:
    """
    Handles IP address related functionalities, including geolocation.
    """
    def __init__(self):
        ipinfo_token = os.getenv('IPINFO_API_TOKEN')
        if not ipinfo_token:
            print("WARNING: IPinfo API token is not configured or is default. Geolocation will not work correctly.")
            raise ValueError("IPinfo API token is not configured.")
        else:
            self.handler = ipinfo.getHandler(ipinfo_token)

    def get_location_from_ip(self, ip_address):
        """
        Gets country and city from an IP address using ipinfo.io.
        Handles loopback addresses as being in the same country/city for local testing.
        """
        if ip_address in ['127.0.0.1', '::1']:
            # For local testing, treat loopback as "local"
            print(f"Detected loopback IP '{ip_address}'. Treating as local.")
            # For this academic project, we assume local means the user's registered country/city.
            # In a real app, you might have a default location or require manual input.
            return {"country": "Local", "city": "Local"} # Placeholder for local
        
        if not self.handler:
            print("IPinfo handler not initialized. Cannot perform geolocation.")
            raise Exception("IPinfo handler not initialized. Cannot perform geolocation.")
        try:
            details = self.handler.getDetails(ip_address)
            return {
                "country": details.country_name,
                "city": details.city if details.city else details.region # Fallback to region if city is empty
            }
        except Exception as e:
            print(f"Error getting IP location for {ip_address}: {e}")
            return None

    @staticmethod
    def get_client_ip(request):
        """
        Retrieves the client's IP address from a Flask request.
        """
        # For a simple local Flask development server, request.remote_addr is usually reliable.
        # In a production environment behind proxies, you might need to check X-Forwarded-For.
        return request.remote_addr