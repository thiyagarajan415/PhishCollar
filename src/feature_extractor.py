import re
from urllib.parse import urlparse
import requests
import whois
from bs4 import BeautifulSoup
from datetime import datetime
import time

class URLFeatureExtractor:
    def __init__(self, url):
        self.raw_url = url
        if not self.raw_url.startswith('http'):
            self.url = 'http://' + self.raw_url
        else:
            self.url = self.raw_url
            
        self.parsed_url = urlparse(self.url)
        self.domain = self.parsed_url.netloc
        
        # Strip 'www.' for accurate domain analysis
        self.clean_domain = self.domain.replace('www.', '')
        self.is_private = bool(re.match(
        r'^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)',
        self.clean_domain))

        # Attempt to grab HTML content and Redirect history
        self.response = None
        self.soup = None
        try:
            # 4-second timeout to prevent server hanging
            if self.is_private:
                self.response = None
                self.soup = None
            else:
                self.response = requests.get(self.url, timeout=4, allow_redirects=True)
                self.soup = BeautifulSoup(self.response.text, 'html.parser')
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass # We handle missing soup in the functions

    # --- 1. LEXICAL FEATURES (URL String Analysis) ---
    def f1_having_ip(self):
        return -1 if re.search(r'\d+\.\d+\.\d+\.\d+', self.domain) else 1

    def f2_url_length(self):
        l = len(self.url)
        if l < 54: return 1
        elif 54 <= l <= 75: return 0
        else: return -1

    def f3_prefix_suffix(self):
        return -1 if '-' in self.clean_domain else 1

    def f4_having_sub_domain(self):
        # Count dots in the clean domain (excluding www)
        dot_count = self.clean_domain.count('.')
        if dot_count == 1: return 1
        elif dot_count == 2: return 0
        else: return -1

    def f5_ssl_state(self):
        # Basic check: did they use https?
        return 1 if self.parsed_url.scheme == 'https' else -1

    def f6_port(self):
        # If a specific port is in the URL and it's not 80 or 443
        port = self.parsed_url.port
        if port and port not in [80, 443]: return -1
        return 1

    def f7_https_token(self):
        # Hackers put 'https' in the domain name to trick users (e.g. http://https-paypal.com)
        return -1 if 'https' in self.clean_domain else 1

    # --- 2. HTML FEATURES (Web Scraping) ---
    def f8_request_url(self):
        if not self.soup: return -1
        # Calculate % of external objects (images, videos)
        external = 0
        total = 0
        for tag in self.soup.find_all(['img', 'audio', 'embed', 'video']):
            total += 1
            src = tag.get('src')
            if src and self.clean_domain not in src and src.startswith('http'):
                external += 1
        
        if total == 0: return 1
        pct = (external / total) * 100
        if pct < 22: return 1
        elif 22 <= pct <= 61: return 0
        else: return -1

    def f9_url_of_anchor(self):
        if not self.soup: return -1
        # Calculate % of <a> tags leading outside or to empty '#'
        suspicious = 0
        total = 0
        for a in self.soup.find_all('a', href=True):
            total += 1
            href = a['href']
            if href == '#' or href.startswith('javascript:') or (self.clean_domain not in href and href.startswith('http')):
                suspicious += 1
        
        if total == 0: return 1
        pct = (suspicious / total) * 100
        if pct < 31: return 1
        elif 31 <= pct <= 67: return 0
        else: return -1

    def f10_links_in_tags(self):
        if not self.soup: return -1
        # % of Links in <meta>, <script> and <link> tags
        external = 0
        total = 0
        for tag in self.soup.find_all(['link', 'script', 'meta']):
            total += 1
            link = tag.get('href') or tag.get('src')
            if link and self.clean_domain not in link and link.startswith('http'):
                external += 1
                
        if total == 0: return 1
        pct = (external / total) * 100
        if pct < 17: return 1
        elif 17 <= pct <= 81: return 0
        else: return -1

    def f11_submitting_to_email(self):
        if not self.soup: return -1
        html_str = str(self.soup).lower()
        return -1 if "mailto:" in html_str or "mail()" in html_str else 1

    def f14_on_mouseover(self):
        if not self.soup: return -1
        return -1 if "window.status" in str(self.soup).lower() else 1

    # --- 3. NETWORK & DNS FEATURES ---
    def f13_redirect(self):
        if not self.response: return -1
        redirects = len(self.response.history)
        if redirects <= 1: return 1
        elif redirects >= 2 and redirects < 4: return 0
        else: return -1

    def f15_age_of_domain(self):
        if self.is_private:
            return -1
        try:
            domain_info = whois.whois(self.clean_domain)
            creation_date = domain_info.creation_date
            if type(creation_date) is list:
                creation_date = creation_date[0]
            
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                return 1 if age_days >= 180 else -1
            return -1
        except:
            return -1 # DNS lookup failed

    def _mock_feature(self, default_val):
        """Used for features requiring paid 3rd party APIs"""
        return default_val

    # --- MASTER COMPILER ---
    def extract(self):
        """Maps our logic to the exact names your AI expects."""
        return {
            'having_IPhaving_IP_Address': self.f1_having_ip(),
            'URLURL_Length': self.f2_url_length(),
            'Prefix_Suffix': self.f3_prefix_suffix(),
            'having_Sub_Domain': self.f4_having_sub_domain(),
            'SSLfinal_State': self.f5_ssl_state(),
            'port': self.f6_port(),
            'HTTPS_token': self.f7_https_token(),
            'Request_URL': self.f8_request_url(),
            'URL_of_Anchor': self.f9_url_of_anchor(),
            'Links_in_tags': self.f10_links_in_tags(),
            'Submitting_to_email': self.f11_submitting_to_email(),
            'Abnormal_URL': 1, # WHOIS hostname check is unreliable in Python, defaulting to 1
            'Redirect': self.f13_redirect(),
            'on_mouseover': self.f14_on_mouseover(),
            'age_of_domain': self.f15_age_of_domain(),
            
            # These 4 require paid API access (Alexa Rank, Google Search API, Ahrefs Backlinks).
            # We mock them to neutral/safe values so the AI relies on the other 15 real features.
            'web_traffic': self._mock_feature(0), 
            'Google_Index': self._mock_feature(1),
            'Links_pointing_to_page': self._mock_feature(0),
            'Statistical_report': self._mock_feature(1)
        }