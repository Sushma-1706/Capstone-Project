"""Utility functions for file handling, validation, and security."""

import os
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import Optional

# Allowed file extensions for analysis
ALLOWED_EXTENSIONS = {".py"}
ALLOWED_ARCHIVE_EXTENSIONS = {".zip"}

# File size limits (in bytes)
MAX_FILE_SIZE = 10 * 1024 * 1024        # 10 MB
MAX_ZIP_SIZE = 50 * 1024 * 1024         # 50 MB
MAX_EXTRACTED_SIZE = 100 * 1024 * 1024   # 100 MB total extracted

# Dangerous path components
DANGEROUS_PATTERNS = ["..", "~", "$"]


def generate_analysis_id() -> str:
    """Generate a unique analysis ID."""
    return f"analysis_{uuid.uuid4().hex[:12]}"


def validate_file_extension(filename: str) -> bool:
    """Check if the file has an allowed extension."""
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS or ext in ALLOWED_ARCHIVE_EXTENSIONS


def is_python_file(filename: str) -> bool:
    """Check if a file is a Python source file."""
    return Path(filename).suffix.lower() == ".py"


def is_zip_file(filename: str) -> bool:
    """Check if a file is a ZIP archive."""
    return Path(filename).suffix.lower() == ".zip"


def validate_file_size(size: int, is_archive: bool = False) -> bool:
    """Validate file size against limits."""
    limit = MAX_ZIP_SIZE if is_archive else MAX_FILE_SIZE
    return size <= limit


def is_path_safe(filepath: str) -> bool:
    """Check for path traversal attacks."""
    normalized = os.path.normpath(filepath)
    # Check for directory traversal
    if ".." in normalized.split(os.sep):
        return False
    # Check for absolute paths within archives
    if os.path.isabs(normalized):
        return False
    # Check for dangerous patterns
    for pattern in DANGEROUS_PATTERNS:
        if pattern in filepath:
            return False
    return True


def create_temp_directory() -> str:
    """Create a secure temporary directory for analysis."""
    temp_dir = tempfile.mkdtemp(prefix="analysis_")
    return temp_dir


def cleanup_temp_directory(temp_dir: str) -> None:
    """Safely remove a temporary directory and all its contents."""
    try:
        if os.path.exists(temp_dir) and temp_dir.startswith(tempfile.gettempdir()):
            shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass


def safe_extract_zip(
    zip_path: str, extract_dir: str
) -> tuple[list[str], list[str]]:
    """
    Safely extract a ZIP file, checking for path traversal and size limits.

    Returns:
        Tuple of (list of extracted Python file paths, list of errors)
    """
    extracted_files: list[str] = []
    errors: list[str] = []
    total_size = 0

    try:
        if not zipfile.is_zipfile(zip_path):
            return [], ["File is not a valid ZIP archive"]

        with zipfile.ZipFile(zip_path, "r") as zf:
            # Check for zip bombs
            for info in zf.infolist():
                total_size += info.file_size
                if total_size > MAX_EXTRACTED_SIZE:
                    return [], [
                        f"Extracted size exceeds limit of "
                        f"{MAX_EXTRACTED_SIZE // (1024 * 1024)} MB"
                    ]

            for info in zf.infolist():
                # Skip directories
                if info.is_dir():
                    continue

                # Path traversal check
                if not is_path_safe(info.filename):
                    errors.append(
                        f"Skipped unsafe path: {info.filename}"
                    )
                    continue

                # Only extract Python files
                if not is_python_file(info.filename):
                    continue

                # Build safe extraction path
                target_path = os.path.normpath(
                    os.path.join(extract_dir, info.filename)
                )

                # Ensure the target is within the extraction directory
                if not target_path.startswith(
                    os.path.normpath(extract_dir)
                ):
                    errors.append(
                        f"Path traversal detected: {info.filename}"
                    )
                    continue

                # Create parent directories
                os.makedirs(os.path.dirname(target_path), exist_ok=True)

                # Extract the file
                with zf.open(info) as source, open(target_path, "wb") as target:
                    target.write(source.read())

                extracted_files.append(target_path)

    except zipfile.BadZipFile:
        errors.append("Corrupted or invalid ZIP file")
    except Exception as e:
        errors.append(f"ZIP extraction error: {str(e)}")

    return extracted_files, errors


def save_uploaded_file(
    content: bytes, filename: str, temp_dir: str
) -> str:
    """Save uploaded file content to the temp directory."""
    safe_name = os.path.basename(filename)
    filepath = os.path.join(temp_dir, safe_name)
    with open(filepath, "wb") as f:
        f.write(content)
    return filepath


def get_results_dir() -> str:
    """Get or create the results directory."""
    results_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "results",
    )
    os.makedirs(results_dir, exist_ok=True)
    return results_dir


def collect_python_files(directory: str) -> list[str]:
    """Collect all Python files in a directory recursively."""
    python_files = []
    for root, _dirs, files in os.walk(directory):
        for fname in files:
            if is_python_file(fname):
                python_files.append(os.path.join(root, fname))
    return python_files
