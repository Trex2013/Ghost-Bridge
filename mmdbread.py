import geoip2.database
db_file = 'GeoLite2-ASN.mmdb' 

def get_org_name(ip_address):
    try:
        with geoip2.database.Reader(db_file) as reader:
            response = reader.asn(ip_address)
            return {
                
                "Organization": response.autonomous_system_organization
            }
    except Exception as e:
        return f"Error: {e}"


target_ip = "43.252.12.76" 
print(get_org_name(target_ip))