# src/connector.py - Fichier principal adapté au template
import os
import sys
import time
import requests
import yaml
from datetime import datetime
from typing import Dict, List, Optional
from pycti import OpenCTIConnectorHelper, get_config_variable

from client_api import ConnectorClient
from config_loader import ConfigConnector
from converter_to_stix import ConverterToStix


class KasperskiConnector:
    """
    Kaspersky Threat Intelligence internal enrichment connector

    This class encapsulates the main actions for enriching observables with Kaspersky TI data.
    It will create a STIX bundle and send it in a RabbitMQ queue.
    """

    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """
        # Load configuration file and connection helper
        self.config = config
        self.helper = helper
        self.client = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper)

        # Define variables
        self.author = None
        self.tlp = None
        self.stix_objects_list = []

    def _collect_intelligence(self, value, obs_id) -> list:
        """
        Collect intelligence from Kaspersky TI and convert into STIX object
        :return: List of STIX objects
        """
        self.helper.connector_logger.info("[KASPERSKY] Starting enrichment...")

        try:
            # Get threat intelligence from Kaspersky TI
            kaspersky_data = self.client.get_threat_intelligence(value, obs_id)

            if not kaspersky_data:
                self.helper.connector_logger.info("[KASPERSKY] No threat intelligence found")
                return []

            # Create the author (Kaspersky)
            self.author = self.converter_to_stix.create_author()

            # Convert Kaspersky data into STIX2 objects
            stix_objects = []

            # Create note with Kaspersky enrichment data
            note = self.converter_to_stix.create_note(kaspersky_data, obs_id)
            if note:
                stix_objects.append(note)

            # Create indicator if reputation is malicious/suspicious
            if kaspersky_data.get("reputation", "").lower() in ["malicious", "suspicious"]:
                indicator = self.converter_to_stix.create_indicator(kaspersky_data, value, obs_id)
                if indicator:
                    stix_objects.append(indicator)

            # Add author to objects
            if self.author:
                stix_objects.append(self.author)

            return stix_objects

        except Exception as e:
            self.helper.connector_logger.error(f"[KASPERSKY] Error collecting intelligence: {str(e)}")
            return []

    def entity_in_scope(self, data) -> bool:
        """
        Security to limit playbook triggers to something other than the initial scope
        :param data: Dictionary of data
        :return: boolean
        """
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_split = data["entity_id"].split("--")
        entity_type = entity_split[0].lower()

        if entity_type in scopes:
            return True
        else:
            return False

    def extract_and_check_markings(self, opencti_entity: dict) -> None:
        """
        Extract TLP, and check if the variable "max_tlp" is less than
        or equal to the markings access of the entity from OpenCTI
        """
        if len(opencti_entity["objectMarking"]) != 0:
            for marking_definition in opencti_entity["objectMarking"]:
                if marking_definition["definition_type"] == "TLP":
                    self.tlp = marking_definition["definition"]

        valid_max_tlp = self.helper.check_max_tlp(self.tlp, self.config.max_tlp)

        if not valid_max_tlp:
            raise ValueError(
                "[KASPERSKY] Do not send any data, TLP of the observable is greater than MAX TLP,"
                "the connector does not have access to this observable, please check the group of the connector user"
            )

    def process_message(self, data: dict) -> str:
        """
        Process the observable created/modified in OpenCTI
        :param data: dict of data to process
        :return: string
        """
        try:
            opencti_entity = data["enrichment_entity"]
            self.extract_and_check_markings(opencti_entity)

            # To enrich the data, add more STIX objects in stix_objects
            self.stix_objects_list = data["stix_objects"]
            observable = data["stix_entity"]

            # Extract information from entity data
            obs_standard_id = observable["id"]
            obs_value = observable["value"]
            obs_type = observable["type"]

            info_msg = "[KASPERSKY] Processing observable for entity type: "
            self.helper.connector_logger.info(info_msg, {"type": obs_type})

            if self.entity_in_scope(data):
                # Collect intelligence from Kaspersky and enrich the entity
                stix_objects = self._collect_intelligence(obs_value, obs_standard_id)

                if stix_objects is not None and len(stix_objects):
                    # Add new objects to existing bundle
                    self.stix_objects_list.extend(stix_objects)
                    return self._send_bundle(self.stix_objects_list)
                else:
                    info_msg = "[KASPERSKY] No information found"
                    return info_msg
            else:
                if not data.get("event_type"):
                    # Return original bundle unchanged if not in scope but from playbook
                    return self._send_bundle(self.stix_objects_list)
                else:
                    raise ValueError(
                        f"Failed to process observable, {opencti_entity['entity_type']} is not a supported entity type."
                    )
        except Exception as err:
            return self.helper.connector_logger.error(
                "[KASPERSKY] Unexpected Error occurred", {"error_message": str(err)}
            )

    def _send_bundle(self, stix_objects: list) -> str:
        """Send STIX bundle to OpenCTI"""
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)

        info_msg = f"[KASPERSKY] Sending {len(bundles_sent)} stix bundle(s) for worker import"
        return info_msg

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        """
        self.helper.listen(message_callback=self.process_message)