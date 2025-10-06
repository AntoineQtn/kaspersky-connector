import pytest
import json
import responses
from unittest.mock import Mock, patch, MagicMock
from stix2 import Note, Indicator, Identity

from src.connector import KasperskiConnector
from src.config_loader import ConfigConnector
from src.client_api import ConnectorClient
from src.converter_to_stix import ConverterToStix


class TestKasperskyConnector:
    """Test cases for Kaspersky connector"""

    @pytest.fixture
    def mock_config(self):
        """Mock configuration for testing"""
        config = {
            "kaspersky": {
                "api_key": "test_api_key",
                "base_url": "https://tip.kaspersky.com/api/v1",
                "max_tlp": "TLP:AMBER",
                "create_indicators": True
            },
            "connector": {
                "scope": "File,Domain-Name,IPv4-Addr,IPv6-Addr,Url"
            }
        }
        return config

    @pytest.fixture
    def mock_helper(self):
        """Mock OpenCTI helper for testing"""
        helper = Mock()
        helper.connect_scope = "File,Domain-Name,IPv4-Addr,IPv6-Addr,Url"
        helper.connector_logger = Mock()
        helper.check_max_tlp = Mock(return_value=True)
        helper.stix2_create_bundle = Mock()
        helper.send_stix2_bundle = Mock(return_value=["bundle1"])
        helper.get_version = Mock(return_value="1.0.0")
        return helper

    @pytest.fixture
    def connector_config(self, mock_config):
        """Create connector configuration"""
        return ConfigConnector(mock_config)

    @pytest.fixture
    def kaspersky_connector(self, mock_config, mock_helper):
        """Create Kaspersky connector instance"""
        config = ConfigConnector(mock_config)
        return KasperskiConnector(config, mock_helper)

    def test_config_loader_valid(self, mock_config):
        """Test valid configuration loading"""
        config = ConfigConnector(mock_config)
        assert config.kaspersky_api_key == "test_api_key"
        assert config.kaspersky_base_url == "https://tip.kaspersky.com/api/v1"
        assert config.max_tlp == "TLP:AMBER"
        assert config.create_indicators is True

    def test_config_loader_missing_api_key(self):
        """Test configuration with missing API key raises error"""
        config = {}
        with pytest.raises(ValueError, match="KASPERSKY_API_KEY is required"):
            ConfigConnector(config)

    def test_entity_in_scope_valid_file(self, kaspersky_connector):
        """Test entity_in_scope with valid file observable"""
        data = {"entity_id": "file--12345678-1234-5678-9abc-123456789abc"}
        assert kaspersky_connector.entity_in_scope(data) is True

    def test_entity_in_scope_valid_domain(self, kaspersky_connector):
        """Test entity_in_scope with valid domain observable"""
        data = {"entity_id": "domain-name--12345678-1234-5678-9abc-123456789abc"}
        assert kaspersky_connector.entity_in_scope(data) is True

    def test_entity_in_scope_invalid_type(self, kaspersky_connector):
        """Test entity_in_scope with invalid observable type"""
        data = {"entity_id": "email-addr--12345678-1234-5678-9abc-123456789abc"}
        assert kaspersky_connector.entity_in_scope(data) is False

    def test_extract_and_check_markings_valid_tlp(self, kaspersky_connector):
        """Test TLP marking validation with valid TLP"""
        opencti_entity = {
            "objectMarking": [
                {"definition_type": "TLP", "definition": "TLP:WHITE"}
            ]
        }
        # Should not raise exception
        kaspersky_connector.extract_and_check_markings(opencti_entity)
        assert kaspersky_connector.tlp == "TLP:WHITE"

    def test_extract_and_check_markings_invalid_tlp(self, kaspersky_connector, mock_helper):
        """Test TLP marking validation with invalid TLP"""
        mock_helper.check_max_tlp.return_value = False
        opencti_entity = {
            "objectMarking": [
                {"definition_type": "TLP", "definition": "TLP:RED"}
            ]
        }
        with pytest.raises(ValueError, match="Do not send any data, TLP"):
            kaspersky_connector.extract_and_check_markings(opencti_entity)


class TestConnectorClient:
    """Test cases for Kaspersky API client"""

    @pytest.fixture
    def mock_helper(self):
        """Mock helper for client testing"""
        helper = Mock()
        helper.connector_logger = Mock()
        helper.get_version = Mock(return_value="1.0.0")
        return helper

    @pytest.fixture
    def mock_config(self):
        """Mock config for client testing"""
        config = Mock()
        config.kaspersky_api_key = "test_key"
        config.kaspersky_base_url = "https://tip.kaspersky.com/api/v1"
        return config

    @pytest.fixture
    def client(self, mock_helper, mock_config):
        """Create client instance"""
        return ConnectorClient(mock_helper, mock_config)

    @responses.activate
    def test_get_file_reputation_success(self, client):
        """Test successful file reputation query"""
        # Mock API response
        responses.add(
            responses.GET,
            "https://tip.kaspersky.com/api/v1/file/reputation",
            json={
                "reputation": "malicious",
                "detection_names": ["Trojan.Win32.Test"],
                "categories": ["malware"],
                "first_seen": "2023-01-01",
                "last_seen": "2023-12-31"
            },
            status=200
        )

        hash_value = "d41d8cd98f00b204e9800998ecf8427e"  # MD5
        obs_id = "file--12345678-1234-5678-9abc-123456789abc"

        result = client.get_threat_intelligence(hash_value, obs_id)

        assert result is not None
        assert result["reputation"] == "malicious"
        assert "Trojan.Win32.Test" in result["detection_names"]

    @responses.activate
    def test_get_domain_reputation_not_found(self, client):
        """Test domain reputation query with 404 response"""
        responses.add(
            responses.GET,
            "https://tip.kaspersky.com/api/v1/domain/reputation",
            status=404
        )

        domain = "example.com"
        obs_id = "domain-name--12345678-1234-5678-9abc-123456789abc"

        result = client.get_threat_intelligence(domain, obs_id)
        assert result is None

    @responses.activate
    def test_api_rate_limit(self, client):
        """Test API rate limiting handling"""
        responses.add(
            responses.GET,
            "https://tip.kaspersky.com/api/v1/ip/reputation",
            status=429
        )

        ip = "192.168.1.1"
        obs_id = "ipv4-addr--12345678-1234-5678-9abc-123456789abc"

        with patch('time.sleep') as mock_sleep:
            result = client.get_threat_intelligence(ip, obs_id)
            mock_sleep.assert_called_once_with(60)
            assert result is None

    def test_unsupported_observable_type(self, client):
        """Test unsupported observable type"""
        value = "test@example.com"
        obs_id = "email-addr--12345678-1234-5678-9abc-123456789abc"

        result = client.get_threat_intelligence(value, obs_id)
        assert result is None


class TestConverterToStix:
    """Test cases for STIX converter"""

    @pytest.fixture
    def mock_helper(self):
        """Mock helper for converter testing"""
        helper = Mock()
        helper.connector_logger = Mock()
        helper.connector_logger.info = Mock()
        helper.connector_logger.error = Mock()
        helper.connector_logger.debug = Mock()
        helper.connector_logger.warning = Mock()
        return helper

    @pytest.fixture
    def converter(self, mock_helper):
        """Create converter instance"""
        return ConverterToStix(mock_helper)

    def test_create_author(self, converter):
        """Test author identity creation"""
        author = converter.create_author()
        assert author.name == "Kaspersky Threat Intelligence Platform"
        assert author.identity_class == "organization"
        assert isinstance(author, Identity)

    def test_create_note_with_full_data(self, converter):
        """Test note creation with complete Kaspersky data"""
        kaspersky_data = {
            "reputation": "malicious",
            "detection_names": ["Trojan.Win32.Test", "Malware.Generic"],
            "categories": ["malware", "trojan"],
            "first_seen": "2023-01-01T00:00:00Z",
            "last_seen": "2023-12-31T23:59:59Z"
        }
        obs_id = "file--12345678-1234-5678-9abc-123456789abc"

        # Debug: Let's see if there's an exception
        try:
            note = converter.create_note(kaspersky_data, obs_id)
        except Exception as e:
            print(f"Exception in create_note: {e}")
            raise

        assert note is not None
        assert isinstance(note, Note)
        # Check that the content contains expected information
        content = note.content
        assert "Malicious" in content
        assert "Trojan.Win32.Test" in content
        assert "malware" in content
        assert "2023-01-01T00:00:00Z" in content
        assert obs_id in note.object_refs
        assert note.created_by_ref == converter.author.id

    def test_create_indicator_malicious(self, converter):
        """Test indicator creation for malicious file"""
        kaspersky_data = {
            "reputation": "malicious",
            "detection_names": ["Trojan.Win32.Test"]
        }
        obs_value = "d41d8cd98f00b204e9800998ecf8427e"  # MD5 hash
        obs_id = "file--12345678-1234-5678-9abc-123456789abc"

        # Mock TLP_WHITE if needed
        with patch('src.converter_to_stix.TLP_WHITE', 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9'):
            indicator = converter.create_indicator(kaspersky_data, obs_value, obs_id)

        # If indicator is None, check what went wrong
        if indicator is None:
            # Check if any errors were logged
            error_calls = converter.helper.connector_logger.error.call_args_list
            debug_calls = converter.helper.connector_logger.debug.call_args_list
            if error_calls:
                pytest.fail(f"Indicator creation failed with errors: {error_calls}")
            elif debug_calls:
                # Check if it was skipped for a valid reason
                skip_messages = [call for call in debug_calls if "Skipping indicator creation" in str(call)]
                if skip_messages:
                    pytest.fail(f"Indicator creation was skipped: {skip_messages}")
            pytest.fail("Indicator creation returned None without clear reason")

        assert isinstance(indicator, Indicator)
        assert "malicious-activity" in indicator.labels
        assert "kaspersky:Trojan.Win32.Test" in indicator.labels
        assert indicator.x_opencti_score == 100
        assert indicator.pattern == "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']"
        assert indicator.pattern_type == "stix"

    def test_create_indicator_suspicious(self, converter):
        """Test indicator creation for suspicious observable"""
        kaspersky_data = {
            "reputation": "suspicious",
            "detection_names": ["Suspicious.Generic"]
        }
        obs_value = "example.com"
        obs_id = "domain-name--12345678-1234-5678-9abc-123456789abc"

        indicator = converter.create_indicator(kaspersky_data, obs_value, obs_id)

        assert indicator is not None
        assert "suspicious-activity" in indicator.labels
        assert "kaspersky:Suspicious.Generic" in indicator.labels
        assert indicator.x_opencti_score == 75
        assert indicator.pattern == "[domain-name:value = 'example.com']"
        assert indicator.pattern_type == "stix"

    def test_create_indicator_clean_reputation(self, converter):
        """Test that no indicator is created for clean reputation"""
        kaspersky_data = {"reputation": "clean"}
        obs_value = "example.com"
        obs_id = "domain-name--12345678-1234-5678-9abc-123456789abc"

        indicator = converter.create_indicator(kaspersky_data, obs_value, obs_id)
        assert indicator is None

    def test_create_stix_pattern_file_md5(self, converter):
        """Test STIX pattern creation for MD5 file hash"""
        pattern = converter.create_stix_pattern("file", "d41d8cd98f00b204e9800998ecf8427e")  # MD5 hash
        assert pattern == "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']"

    def test_create_stix_pattern_file_sha1(self, converter):
        """Test STIX pattern creation for SHA-1 file hash"""
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # SHA-1 hash (40 chars)
        pattern = converter.create_stix_pattern("file", sha1_hash)
        assert pattern == f"[file:hashes.SHA-1 = '{sha1_hash}']"

    def test_create_stix_pattern_file_sha256(self, converter):
        """Test STIX pattern creation for SHA-256 file hash"""
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # SHA-256 hash (64 chars)
        pattern = converter.create_stix_pattern("file", sha256_hash)
        assert pattern == f"[file:hashes.SHA-256 = '{sha256_hash}']"

    def test_create_stix_pattern_domain(self, converter):
        """Test STIX pattern creation for domain"""
        pattern = converter.create_stix_pattern("domain-name", "example.com")
        assert pattern == "[domain-name:value = 'example.com']"

    def test_create_stix_pattern_ipv4(self, converter):
        """Test STIX pattern creation for IPv4"""
        pattern = converter.create_stix_pattern("ipv4-addr", "192.168.1.1")
        assert pattern == "[ipv4-addr:value = '192.168.1.1']"

    def test_create_stix_pattern_url(self, converter):
        """Test STIX pattern creation for URL"""
        pattern = converter.create_stix_pattern("url", "https://example.com/malicious")
        assert pattern == "[url:value = 'https://example.com/malicious']"

    def test_create_stix_pattern_unsupported(self, converter):
        """Test STIX pattern creation for unsupported type"""
        pattern = converter.create_stix_pattern("unsupported-type", "value")
        assert pattern is None

    def test_create_stix_pattern_file_unsupported_hash(self, converter):
        """Test STIX pattern creation for unsupported hash length"""
        # Hash with unsupported length
        unsupported_hash = "abc123"
        pattern = converter.create_stix_pattern("file", unsupported_hash)
        assert pattern is None


class TestKasperskyConnectorIntegration:
    """Integration tests for the complete connector workflow"""

    @pytest.fixture
    def mock_data(self):
        """Mock data for process_message testing"""
        return {
            "entity_id": "file--12345678-1234-5678-9abc-123456789abc",
            "enrichment_entity": {
                "entity_id": "file--12345678-1234-5678-9abc-123456789abc",
                "entity_type": "File",
                "objectMarking": [
                    {"definition_type": "TLP", "definition": "TLP:WHITE"}
                ]
            },
            "stix_objects": [],
            "stix_entity": {
                "id": "file--12345678-1234-5678-9abc-123456789abc",
                "type": "file",
                "value": "d41d8cd98f00b204e9800998ecf8427e"
            }
        }

    @pytest.fixture
    def kaspersky_response_malicious(self):
        """Mock malicious Kaspersky response"""
        return {
            "reputation": "malicious",
            "detection_names": ["Trojan.Win32.Test"],
            "categories": ["malware"],
            "first_seen": "2023-01-01T00:00:00Z",
            "last_seen": "2023-12-31T23:59:59Z"
        }

    @pytest.fixture
    def kaspersky_connector(self):
        """Create Kaspersky connector instance for integration tests"""
        from unittest.mock import Mock

        # Mock configuration
        mock_config = {
            "kaspersky": {
                "api_key": "test_api_key",
                "base_url": "https://tip.kaspersky.com/api/v1",
                "max_tlp": "TLP:AMBER",
                "create_indicators": True
            },
            "connector": {
                "scope": "File,Domain-Name,IPv4-Addr,IPv6-Addr,Url"
            }
        }

        # Mock OpenCTI helper
        mock_helper = Mock()
        mock_helper.connect_scope = "File,Domain-Name,IPv4-Addr,IPv6-Addr,Url"
        mock_helper.connector_logger = Mock()
        mock_helper.check_max_tlp = Mock(return_value=True)
        mock_helper.stix2_create_bundle = Mock(return_value="mock_bundle")
        mock_helper.send_stix2_bundle = Mock(return_value=["bundle1"])
        mock_helper.get_version = Mock(return_value="1.0.0")

        config = ConfigConnector(mock_config)
        return KasperskiConnector(config, mock_helper)

    @patch('src.client_api.ConnectorClient.get_threat_intelligence')
    def test_process_message_success_with_indicator(self, mock_get_ti, kaspersky_connector, mock_data,
                                                    kaspersky_response_malicious):
        """Test complete message processing with indicator creation"""
        # Mock the API response
        mock_get_ti.return_value = kaspersky_response_malicious

        # Process the message
        result = kaspersky_connector.process_message(mock_data)

        # Verify the result
        assert "[KASPERSKY] Sending" in result
        assert "stix bundle(s)" in result

        # Verify API was called
        mock_get_ti.assert_called_once_with("d41d8cd98f00b204e9800998ecf8427e",
                                            "file--12345678-1234-5678-9abc-123456789abc")

    @patch('src.client_api.ConnectorClient.get_threat_intelligence')
    def test_process_message_no_data_found(self, mock_get_ti, kaspersky_connector, mock_data):
        """Test message processing when no threat intelligence is found"""
        # Mock no data found
        mock_get_ti.return_value = None

        # Process the message
        result = kaspersky_connector.process_message(mock_data)

        # Verify the result
        assert "[KASPERSKY] No information found" in result

    def test_process_message_out_of_scope(self, kaspersky_connector, mock_data):
        """Test message processing with out-of-scope observable"""
        # Change to unsupported type
        mock_data["entity_id"] = "email-addr--12345678-1234-5678-9abc-123456789abc"
        mock_data["enrichment_entity"]["entity_id"] = "email-addr--12345678-1234-5678-9abc-123456789abc"
        mock_data["enrichment_entity"]["entity_type"] = "Email-Addr"
        mock_data["event_type"] = "create"  # Trigger out-of-scope error

        # Process the message
        result = kaspersky_connector.process_message(mock_data)

        # Should get error about unsupported entity type
        assert result is not None  # Error logged but function returns