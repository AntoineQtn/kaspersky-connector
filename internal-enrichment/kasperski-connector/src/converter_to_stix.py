import uuid
from datetime import datetime, timezone
from typing import Dict, Optional
from stix2 import Note, Indicator, Identity, TLP_WHITE
from pycti import OpenCTIConnectorHelper


class ConverterToStix:
    """Convert Kaspersky data to STIX objects"""

    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper
        # Initialiser l'auteur dans le constructeur
        self.author = self.create_author()

    def create_author(self) -> Identity:
        """Create Kaspersky as author identity"""
        return Identity(
            name="Kaspersky Threat Intelligence Platform",
            identity_class="organization",
            description="Kaspersky Threat Intelligence Platform provides threat intelligence data",
        )

    def create_note(self, kaspersky_data: Dict, obs_id: str) -> Optional[Note]:
        """
        Create STIX Note from Kaspersky data
        :param kaspersky_data: Data from Kaspersky API
        :param obs_id: Observable STIX ID
        :return: STIX Note object
        """
        try:
            content = "Kaspersky Threat Intelligence Enrichment:\n"
            reputation = kaspersky_data.get("reputation")
            detection_names = kaspersky_data.get("detection_names")
            categories = kaspersky_data.get("categories")
            first_seen = kaspersky_data.get("first_seen")
            last_seen = kaspersky_data.get("last_seen")

            if reputation:
                content += f"- **Reputation:** {reputation.capitalize()}\n"
            if detection_names:
                content += f"- **Detection Names:** {', '.join(detection_names)}\n"
            if categories:
                content += f"- **Categories:** {', '.join(categories)}\n"
            if first_seen:
                content += f"- **First Seen:** {first_seen}\n"
            if last_seen:
                content += f"- **Last Seen:** {last_seen}\n"

            if not any([reputation, detection_names, categories, first_seen, last_seen]):
                self.helper.connector_logger.info("[KASPERSKY] No meaningful data to create a note.")
                return None

            note = Note(
                abstract=f"Kaspersky Enrichment for {obs_id.split('--')[0]}",
                content=content,
                object_refs=[obs_id],
                created_by_ref=self.author.id,
                object_marking_refs=[TLP_WHITE],
                valid_from=datetime.now(timezone.utc)
            )
            self.helper.connector_logger.info(f"[KASPERSKY] Created note for {obs_id}")
            return note
        except Exception as e:
            self.helper.connector_logger.error(f"[KASPERSKY] Error creating note: {str(e)}")
            return None

    def create_indicator(self, kaspersky_data: Dict, obs_value: str, obs_id: str) -> Optional[Indicator]:
        """
        Create STIX Indicator from Kaspersky data
        :param kaspersky_data: Data from Kaspersky API
        :param obs_value: Observable value
        :param obs_id: Observable STIX ID
        :return: STIX Indicator object
        """
        try:
            reputation = kaspersky_data.get("reputation", "").lower()

            if reputation not in ["malicious", "suspicious"]:
                self.helper.connector_logger.debug(
                    f"[KASPERSKY] Skipping indicator creation for reputation: {reputation}")
                return None

            # Create STIX pattern based on observable type
            obs_type = obs_id.split("--")[0] if "--" in obs_id else None
            if not obs_type:
                self.helper.connector_logger.error(f"[KASPERSKY] Invalid observable ID format: {obs_id}")
                return None

            pattern = self.create_stix_pattern(obs_type, obs_value)

            if not pattern:
                self.helper.connector_logger.error(f"[KASPERSKY] Could not create STIX pattern for type: {obs_type}")
                return None

            # Map reputation to score
            score = 100 if reputation == "malicious" else 75

            labels = ["malicious-activity"] if reputation == "malicious" else ["suspicious-activity"]

            # Add detection names as labels
            detection_names = kaspersky_data.get("detection_names", [])
            if detection_names:
                labels.extend([f"kaspersky:{name}" for name in detection_names[:3]])

            # Ajout de l'attribut pattern_type requis
            indicator = Indicator(
                pattern=pattern,
                pattern_type="stix",  # <-- C'est la ligne qu'il faut ajouter
                labels=labels,
                valid_from=datetime.now(timezone.utc),
                x_opencti_score=score,
                x_opencti_detection=True,
                object_marking_refs=[TLP_WHITE]
            )

            self.helper.connector_logger.info(f"[KASPERSKY] Created indicator for {obs_type}: {obs_value}")
            return indicator

        except Exception as e:
            self.helper.connector_logger.error(f"[KASPERSKY] Error creating indicator: {str(e)}")
            return None

    def create_stix_pattern(self, obs_type: str, obs_value: str) -> Optional[str]:
        """
        Create a STIX pattern string based on observable type and value.
        :param obs_type: Type of the observable (e.g., "file", "domain-name")
        :param obs_value: Value of the observable
        :return: STIX pattern string
        """
        try:
            pattern = None
            if obs_type == "file":
                # Assuming obs_value is a hash (MD5, SHA-1, SHA-256)
                if len(obs_value) == 32:  # MD5
                    pattern = f"[file:hashes.MD5 = '{obs_value}']"
                elif len(obs_value) == 40:  # SHA-1
                    pattern = f"[file:hashes.SHA-1 = '{obs_value}']"
                elif len(obs_value) == 64:  # SHA-256
                    pattern = f"[file:hashes.SHA-256 = '{obs_value}']"
                else:
                    self.helper.connector_logger.warning(f"[KASPERSKY] Unsupported file hash length for pattern: {obs_value}")
            elif obs_type == "domain-name":
                pattern = f"[domain-name:value = '{obs_value}']"
            # Ajoutez d'autres types si nécessaire (e.g., "url", "ipv4-addr")
            elif obs_type == "url":
                pattern = f"[url:value = '{obs_value}']"
            elif obs_type == "ipv4-addr":
                pattern = f"[ipv4-addr:value = '{obs_value}']"
            else:
                self.helper.connector_logger.warning(f"[KASPERSKY] Unsupported observable type for STIX pattern: {obs_type}")

            if pattern:
                self.helper.connector_logger.debug(f"[KASPERSKY] Created STIX pattern for {obs_type}: {pattern}")
            return pattern
        except Exception as e:
            self.helper.connector_logger.error(f"[KASPERSKY] Error creating STIX pattern for {obs_type} {obs_value}: {str(e)}")
            return None