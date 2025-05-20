import requests # You might need to install this library: pip install requests
import socket

def is_ip_from_countries(ip_address: str, allowed_countries: list) -> bool:
    """
    Checks if a given IP address is from one of the specified countries.

    Args:
        ip_address (str): The IP address to check (e.g., "8.8.8.8").
        allowed_countries (list): A list of country names (e.g., ["United States", "Canada"]).

    Returns:
        bool: True if the IP is from one of the allowed countries, False otherwise.
              Returns False if there's an error during the lookup.
    """
    if not ip_address or not isinstance(ip_address, str):
        print("Error: Invalid IP address provided.")
        return False
    if not allowed_countries or not isinstance(allowed_countries, list):
        print("Error: Invalid list of allowed countries provided.")
        return False

    # Normalize the allowed_countries list to lowercase for case-insensitive comparison
    normalized_allowed_countries = [country.lower() for country in allowed_countries]

    try:
        # Using ip-api.com for geolocation. It's free for non-commercial use.
        # For other fields or more robust solutions, you might need an API key or a different service.
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode"
        response = requests.get(url, timeout=5) # Added a timeout of 5 seconds
        response.raise_for_status()  # Raises an HTTPError for bad responses (4XX or 5XX)

        data = response.json()

        if data.get("status") == "success":
            country_name = data.get("country")
            if country_name:
                print(f"IP Address: {ip_address}, Detected Country: {country_name}")
                return country_name.lower() in normalized_allowed_countries
            else:
                print(f"Warning: Country information not found for IP {ip_address} in API response.")
                return False
        else:
            error_message = data.get("message", "Unknown error from API")
            print(f"Error looking up IP {ip_address}: {error_message}")
            # Specific handling for reserved range or private IP addresses
            if "reserved range" in error_message.lower() or "private range" in error_message.lower():
                print(f"Note: {ip_address} is a reserved or private IP address and cannot be geolocated externally.")
            return False

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to geolocation service: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False
    


local_ip = '152.250.68.97'

countries_to_check = ["United States", "Canada"]
countries_to_check_br_de = ["Brazil", "Germany"]

print(f"\nChecking if {local_ip} is in {countries_to_check}:")
result = is_ip_from_countries(local_ip, countries_to_check)
print(f"Result: {result}")
