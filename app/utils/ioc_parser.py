import re

IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

DOMAIN_REGEX = (
    r"\b(?:[a-zA-Z0-9-]+\.)+"
    r"(?:com|net|org|edu|gov|io|co|ru|in|uk|xyz|info|biz)\b"
)

URL_REGEX = r"https?://[^\s]+"
MD5_REGEX = r"\b[a-fA-F0-9]{32}\b"
SHA1_REGEX = r"\b[a-fA-F0-9]{40}\b"
SHA256_REGEX = r"\b[a-fA-F0-9]{64}\b"

def extract_iocs(text):

    if not text:
        return []

    indicators = []

    ips = re.findall(IP_REGEX, text)

    for ip in ips:

        indicators.append({

            "value": ip,

            "type": "IP"

        })

    domains=re.findall(DOMAIN_REGEX,text)
    for domain in domains:
        indicators.append({
            
            "value": domain,
            "type": "Domain"

        })

    # Extract URLs
    urls = re.findall(URL_REGEX, text)

    for url in urls:

        indicators.append({

            "value": url,

            "type": "URL"
        })
        #   Extract MD5 Hashes
        md5_hashes = re.findall(MD5_REGEX, text)
        for md5 in md5_hashes:

            indicators.append({

                "value": md5,

                "type": "MD5"
            })
            
        # Extract SHA1 Hashes
        # -----------------------------

        sha1_hashes = re.findall(SHA1_REGEX, text)
        for sha1 in sha1_hashes:

            indicators.append({

                "value": sha1,

                "type": "SHA1"

            })
                  
        # Extract SHA256 Hashes
        # ---------------------------
        sha256_hashes = re.findall(SHA256_REGEX, text)

        for sha256 in sha256_hashes:

            indicators.append({

                "value": sha256,

                "type": "SHA256"

            })
    return indicators