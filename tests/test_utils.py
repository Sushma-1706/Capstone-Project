import pytest
from app.utils.file_utils import is_path_safe, validate_file_extension

def test_path_safety():
    assert is_path_safe("normal_file.py") == True
    assert is_path_safe("dir/file.py") == True
    assert is_path_safe("../file.py") == False
    assert is_path_safe("/etc/passwd") == False
    assert is_path_safe("~/secret.py") == False
    assert is_path_safe("foo/../bar.py") == False

def test_file_extension():
    assert validate_file_extension("test.py") == True
    assert validate_file_extension("test.zip") == True
    assert validate_file_extension("test.txt") == False
    assert validate_file_extension("test") == False
