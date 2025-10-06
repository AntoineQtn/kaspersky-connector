# Makefile - Commandes pour les tests
.PHONY: test test-unit test-integration test-coverage install-test-deps clean

# Install test dependencies
install-test-deps:
	pip install -r test_requirements.txt

# Run all tests
test: install-test-deps
	pytest tests/

# Run unit tests only
test-unit: install-test-deps
	pytest tests/ -m "not integration"

# Run integration tests only
test-integration: install-test-deps
	pytest tests/ -m integration

# Run tests with coverage
test-coverage: install-test-deps
	pytest tests/ --cov=src --cov-report=html --cov-report=term

# Clean test artifacts
clean:
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete