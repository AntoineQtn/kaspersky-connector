import os
from pycti import get_config_variable


class ConfigConnector:
    """Configuration loader for Kaspersky connector"""

    def __init__(self, config):
        """
        Initialize the connector with necessary configuration environment variables
        """
        # Kaspersky TI configuration
        self.kaspersky_api_key = get_config_variable(
            "KASPERSKY_API_KEY", ["kaspersky", "api_key"], config
        )
        self.kaspersky_base_url = get_config_variable(
            "KASPERSKY_BASE_URL",
            ["kaspersky", "base_url"],
            config,
            default="https://tip.kaspersky.com/api/v1"
        )
        self.max_tlp = get_config_variable(
            "KASPERSKY_MAX_TLP", ["kaspersky", "max_tlp"], config, default="TLP:AMBER"
        )
        self.create_indicators = get_config_variable(
            "KASPERSKY_CREATE_INDICATORS",
            ["kaspersky", "create_indicators"],
            config,
            default=True,
        )

        # Validate required configuration
        if not self.kaspersky_api_key:
            raise ValueError("KASPERSKY_API_KEY is required")