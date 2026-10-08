import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

def test_health_check():
    """Test the /health endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "tools" in data

def test_invalid_file_extension():
    """Test uploading a file with an invalid extension."""
    response = client.post(
        "/analyze",
        files={"file": ("test.txt", b"import sys\n")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "failed"
    assert "Unsupported file type" in data["errors"][0]

def test_empty_file():
    """Test uploading an empty file."""
    response = client.post(
        "/analyze",
        files={"file": ("test.py", b"")}
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["errors"]) > 0
    assert "empty" in data["errors"][0].lower()

def test_syntax_error():
    """Test uploading a file with python syntax error."""
    response = client.post(
        "/analyze",
        files={"file": ("test.py", b"def invalid_syntax: pass")}
    )
    assert response.status_code == 200
    data = response.json()
    
    # Needs to be partial, syntax error prevents AST but allows tools to run on text
    assert data["status"] in ["completed", "partial"]
    
    # Check if a syntax error finding was generated
    syntax_findings = [f for f in data["findings"] if f["type"] == "SYNTAX_ERROR"]
    assert len(syntax_findings) >= 1
    assert syntax_findings[0]["source"] == "AST"

def test_pylint_and_bandit_detects_issues():
    """Test with intentional bad code."""
    bad_code = b'''
import subprocess

def process():
    pwd = "hardcoded_password"
    subprocess.run("ls " + pwd, shell=True)

class poorlyNamedClass:
    pass
'''
    response = client.post(
        "/analyze",
        files={"file": ("test.py", bad_code)}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["completed", "partial"]
    
    findings = data["findings"]
    
    # Should detect shell=True in subprocess (Bandit)
    bandit_issues = [f for f in findings if f["source"] == "Bandit" and f["rule"] == "B602"]
    assert len(bandit_issues) > 0
    
    # Should detect poorly named class (Pylint)
    pylint_issues = [f for f in findings if f["source"] == "Pylint" and f["category"] == "invalid-name"]
    assert len(pylint_issues) > 0

def test_get_results_not_found():
    """Test getting results for a non-existent analysis."""
    response = client.get("/results/non_existent_id")
    assert response.status_code == 404
