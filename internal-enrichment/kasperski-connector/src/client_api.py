import requests
import time
from typing import Dict, Optional
from pycti import OpenCTIConnectorHelper

from config_loader import ConfigConnector


class ConnectorClient:
    """Client for Kaspersky Threat Intelligence Platform API"""

    def __init__(self, helper: OpenCTIConnectorHelper, config: ConfigConnector):
        self.helper = helper
        self.config = config

        # API configuration
        self.base_url = config.kaspersky_base_url
        self.api_key = config.kaspersky_api_key

        # Headers for API requests
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": f"OpenCTI-Kaspersky-Connector/{helper.get_version()}"
        }

    def _make_request(self, endpoint: str, params: Dict = None) -> Optional[Dict]:
        """Make API request to Kaspersky TIP"""
        try:
            url = f"{self.base_url}/{endpoint}"
            response = requests.get(url, headers=self.headers, params=params, timeout=30)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                self.helper.connector_logger.info(f"[KASPERSKY] No data found for query: {params}")
                return None
            elif response.status_code == 429:
                self.helper.connector_logger.warning("[KASPERSKY] Rate limit exceeded, waiting...")
                time.sleep(60)
                return None
            else:
                self.helper.connector_logger.error(
                    f"[KASPERSKY] API request failed: {response.status_code} - {response.text}"
                )
                return None

        except Exception as e:
            self.helper.connector_logger.error(f"[KASPERSKY] Error making API request: {str(e)}")
            return None

    def get_threat_intelligence(self, value: str, obs_id: str) -> Optional[Dict]:
        """
        Get threat intelligence from Kaspersky based on observable value
        :param value: Observable value
        :param obs_id: Observable STIX ID to determine type
        :return: Dictionary with threat intelligence data
        """
        # Determine observable type from STIX ID
        obs_type = obs_id.split("--")[0]

        if obs_type == "file":
            return self._get_file_reputation(value)
        elif obs_type == "domain-name":
            return self._get_domain_reputation(value)
        elif obs_type in ["ipv4-addr", "ipv6-addr"]:
            return self._get_ip_reputation(value)
        elif obs_type == "url":
            return self._get_url_reputation(value)
        else:
            self.helper.connector_logger.info(f"[KASPERSKY] Observable type {obs_type} not supported")
            return None

    def _get_file_reputation(self, hash_value: str) -> Optional[Dict]:
        """Get file reputation from Kaspersky"""
        # Determine hash type based on length
        hash_length = len(hash_value)
        if hash_length == 32:
            params = {"md5": hash_value}
        elif hash_length == 40:
            params = {"sha1": hash_value}
        elif hash_length == 64:
            params = {"sha256": hash_value}
        else:
            return None

        return self._make_request("file/reputation", params)

    def _get_domain_reputation(self, domain: str) -> Optional[Dict]:
        """Get domain reputation from Kaspersky"""
        params = {"domain": domain}
        return self._make_request("domain/reputation", params)

    def _get_ip_reputation(self, ip: str) -> Optional[Dict]:
        """Get IP reputation from Kaspersky"""
        params = {"ip": ip}
        return self._make_request("ip/reputation", params)

    def _get_url_reputation(self, url: str) -> Optional[Dict]:
        """Get URL reputation from Kaspersky"""
        params = {"url": url}
        return self._make_request("url/reputation", params)
