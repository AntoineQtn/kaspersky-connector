import os
import sys
import time
import yaml

# Ajouter le répertoire src au PYTHONPATH
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from pycti import OpenCTIConnectorHelper
from connector import KasperskiConnector
from config_loader import ConfigConnector


def main():
    """Main function to start the Kaspersky connector"""
    try:
        # Load configuration
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.SafeLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        # Initialize connector configuration and helper
        connector_config = ConfigConnector(config)
        helper = OpenCTIConnectorHelper(config)

        # Initialize and start connector
        kaspersky_connector = KasperskiConnector(connector_config, helper)
        kaspersky_connector.run()

    except Exception as e:
        print(f"[ERROR] Failed to start Kaspersky connector: {str(e)}")
        time.sleep(10)
        sys.exit(1)


if __name__ == "__main__":
    main()
