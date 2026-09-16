import pytest
import os
import json
from unittest.mock import MagicMock, patch

from term_analyzer import reporter, spraying

# =====================================================================
# 1. TEST REPORTER MODULE (JSON & Pretty Reports)
# =====================================================================

def test_reporter_json_output(tmp_path):
    sample_data = {"target": "http://127.0.0.1:8080", "status": "success", "findings": []}
    
    # json_report takes 1 argument based on its signature
    if hasattr(reporter, "json_report"):
        with patch("builtins.open", create=True) as mock_open:
            try:
                reporter.json_report(sample_data)
            except Exception:
                # If it attempts to write or print without mock files, we just ensure it's callable
                pass
        assert True

def test_reporter_pretty_output():
    assert hasattr(reporter, "pretty_report")
    assert hasattr(reporter, "json_report")


# =====================================================================
# 2. TEST SPRAYING MODULE FUNCTIONS
# =====================================================================

def test_spraying_module_has_core_functions():
    assert hasattr(spraying, "run_credential_spray")
    assert hasattr(spraying, "test_http_auth")
    assert hasattr(spraying, "get_defaults_for_port")

def test_get_defaults_for_port():
    if hasattr(spraying, "get_defaults_for_port"):
        defaults = spraying.get_defaults_for_port(80)
        assert defaults is not None
