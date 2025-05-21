import ipinfo
import socket
from config import IPINFO_API_TOKEN

class IPUtils:
    """
    Handles IP address related functionalities, including geolocation.
    """
    def __init__(self, ipinfo_token=IPINFO_API_TOKEN):
        if not ipinfo_token or ipinfo_token == 'YOUR_IPINFO_API_TOKEN':
            print("WARNING: IPinfo API token is not configured or is default. Geolocation will not work correctly.")
            self.handler = None
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
            return None

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

# Example Usage (for testing ip_utils independently)
if __name__ == '__main__':
    ip_util = IPUtils()

    # Test with a public IP (example IP from ipinfo.io docs)
    test_ip_public = "8.8.8.8"
    print(f"Getting location for public IP: {test_ip_public}")
    location_public = ip_util.get_location_from_ip(test_ip_public)
    if location_public:
        print(f"  Country: {location_public['country']}, City: {location_public['city']}")
    else:
        print("  Failed to get location for public IP.")

    # Test with loopback IP
    test_ip_loopback_ipv4 = "127.0.0.1"
    print(f"\nGetting location for loopback IPv4: {test_ip_loopback_ipv4}")
    location_loopback_ipv4 = ip_util.get_location_from_ip(test_ip_loopback_ipv4)
    if location_loopback_ipv4:
        print(f"  Country: {location_loopback_ipv4['country']}, City: {location_loopback_ipv4['city']}")
    else:
        print("  Failed to get location for loopback IPv4.")

    test_ip_loopback_ipv6 = "::1"
    print(f"\nGetting location for loopback IPv6: {test_ip_loopback_ipv6}")
    location_loopback_ipv6 = ip_util.get_location_from_ip(test_ip_loopback_ipv6)
    if location_loopback_ipv6:
        print(f"  Country: {location_loopback_ipv6['country']}, City: {location_loopback_ipv6['city']}")
    else:
        print("  Failed to get location for loopback IPv6.")