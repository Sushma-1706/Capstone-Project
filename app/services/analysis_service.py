"""Analysis orchestration service — coordinates all analysis tools."""

import os
from datetime import datetime, timezone
from typing import Optional

from app.analyzers.bandit_analyzer import BanditAnalyzer
from app.analyzers.pylint_analyzer import PylintAnalyzer
from app.analyzers.radon_analyzer import RadonAnalyzer
from app.analyzers.sonarqube_analyzer import SonarQubeAnalyzer
from app.models.analysis import (
    AnalysisResult,
    AnalysisStatus,
    FileInfo,
    ToolReport,
    ToolStatus,
)
from app.models.finding import ComplexityResult, Finding
from app.parsers.python_parser import PythonParser
from app.services.storage_service import StorageService
from app.utils.file_utils import (
    cleanup_temp_directory,
    collect_python_files,
    create_temp_directory,
    generate_analysis_id,
    is_python_file,
    is_zip_file,
    safe_extract_zip,
    save_uploaded_file,
    validate_file_extension,
    validate_file_size,
)


class AnalysisService:
    """Orchestrates the full static-analysis pipeline."""

    def __init__(
        self,
        sonar_url: str = "http://localhost:9000",
        sonar_token: Optional[str] = None,
        sonar_enabled: bool = False,
    ):
        self.parser = PythonParser()
        self.pylint = PylintAnalyzer()
        self.bandit = BanditAnalyzer()
        self.radon = RadonAnalyzer()
        self.sonarqube = SonarQubeAnalyzer(
            sonar_url=sonar_url, sonar_token=sonar_token
        )
        self.sonar_enabled = sonar_enabled
        self.storage = StorageService()

    async def analyze_file(
        self, content: bytes, filename: str
    ) -> AnalysisResult:
        """
        Analyze a single uploaded file or ZIP archive.

        Args:
            content: Raw file bytes.
            filename: Original filename.

        Returns:
            Complete AnalysisResult with all findings.
        """
        analysis_id = generate_analysis_id()
        result = AnalysisResult(
            analysis_id=analysis_id,
            status=AnalysisStatus.RUNNING,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # Validate file extension
        if not validate_file_extension(filename):
            result.status = AnalysisStatus.FAILED
            result.errors.append(
                f"Unsupported file type: {filename}. "
                "Allowed: .py, .zip"
            )
            self.storage.save(result)
            return result

        # Validate file size
        is_archive = is_zip_file(filename)
        if not validate_file_size(len(content), is_archive=is_archive):
            limit = "50 MB" if is_archive else "10 MB"
            result.status = AnalysisStatus.FAILED
            result.errors.append(f"File exceeds size limit of {limit}")
            self.storage.save(result)
            return result

        # Validate non-empty
        if len(content) == 0:
            result.status = AnalysisStatus.FAILED
            result.errors.append("Uploaded file is empty")
            self.storage.save(result)
            return result

        temp_dir = create_temp_directory()

        try:
            if is_zip_file(filename):
                result = await self._analyze_zip(
                    content, filename, temp_dir, result
                )
            elif is_python_file(filename):
                result = await self._analyze_single_file(
                    content, filename, temp_dir, result
                )
            else:
                result.status = AnalysisStatus.FAILED
                result.errors.append(f"Unsupported file type: {filename}")
        finally:
            cleanup_temp_directory(temp_dir)

        # Compute summary and save
        result.compute_summary()
        if result.status == AnalysisStatus.RUNNING:
            result.status = (
                AnalysisStatus.COMPLETED
                if not result.errors
                else AnalysisStatus.PARTIAL
            )
        self.storage.save(result)
        return result

    async def _analyze_single_file(
        self,
        content: bytes,
        filename: str,
        temp_dir: str,
        result: AnalysisResult,
    ) -> AnalysisResult:
        """Analyze a single Python file through the full pipeline."""
        # Save file to temp
        try:
            source_code = content.decode("utf-8")
        except UnicodeDecodeError:
            result.status = AnalysisStatus.FAILED
            result.errors.append("File is not valid UTF-8 encoded text")
            return result

        file_path = save_uploaded_file(content, filename, temp_dir)
        relative_name = os.path.basename(filename)

        # --- Stage 1: AST Parsing ---
        file_info, ast_findings = self.parser.parse_file(
            source_code, relative_name
        )
        if file_info:
            result.files_analyzed.append(file_info)
        result.findings.extend(ast_findings)
        result.tool_reports["AST"] = ToolReport(
            status=ToolStatus.SUCCESS,
            findings_count=len(ast_findings),
        )
        result.tools_used.append("AST")

        # --- Stage 2: Pylint ---
        try:
            pylint_findings = self.pylint.analyze(
                file_path, base_dir=temp_dir
            )
            result.findings.extend(pylint_findings)
            result.tool_reports["Pylint"] = ToolReport(
                status=ToolStatus.SUCCESS,
                findings_count=len(pylint_findings),
            )
            result.tools_used.append("Pylint")
        except Exception as e:
            result.tool_reports["Pylint"] = ToolReport(
                status=ToolStatus.FAILED, message=str(e)
            )
            result.errors.append(f"Pylint failed: {e}")

        # --- Stage 3: Bandit ---
        try:
            bandit_findings = self.bandit.analyze(
                file_path, base_dir=temp_dir
            )
            result.findings.extend(bandit_findings)
            result.tool_reports["Bandit"] = ToolReport(
                status=ToolStatus.SUCCESS,
                findings_count=len(bandit_findings),
            )
            result.tools_used.append("Bandit")
        except Exception as e:
            result.tool_reports["Bandit"] = ToolReport(
                status=ToolStatus.FAILED, message=str(e)
            )
            result.errors.append(f"Bandit failed: {e}")

        # --- Stage 4: Radon ---
        try:
            complexity_result, radon_findings = self.radon.analyze(
                file_path, base_dir=temp_dir
            )
            result.findings.extend(radon_findings)
            result.complexity = complexity_result
            result.tool_reports["Radon"] = ToolReport(
                status=ToolStatus.SUCCESS,
                findings_count=len(radon_findings),
            )
            result.tools_used.append("Radon")
        except Exception as e:
            result.tool_reports["Radon"] = ToolReport(
                status=ToolStatus.FAILED, message=str(e)
            )
            result.errors.append(f"Radon failed: {e}")

        # --- Stage 5: SonarQube (optional) ---
        if self.sonar_enabled:
            try:
                if self.sonarqube.is_available():
                    sonar_findings = self.sonarqube.analyze(
                        temp_dir, base_dir=temp_dir
                    )
                    result.findings.extend(sonar_findings)
                    result.tool_reports["SonarQube"] = ToolReport(
                        status=ToolStatus.SUCCESS,
                        findings_count=len(sonar_findings),
                    )
                    result.tools_used.append("SonarQube")
                else:
                    result.tool_reports["SonarQube"] = ToolReport(
                        status=ToolStatus.UNAVAILABLE,
                        message="SonarQube server is not reachable",
                    )
            except Exception as e:
                result.tool_reports["SonarQube"] = ToolReport(
                    status=ToolStatus.FAILED, message=str(e)
                )
        else:
            result.tool_reports["SonarQube"] = ToolReport(
                status=ToolStatus.SKIPPED,
                message="SonarQube integration is disabled",
            )

        return result

    async def _analyze_zip(
        self,
        content: bytes,
        filename: str,
        temp_dir: str,
        result: AnalysisResult,
    ) -> AnalysisResult:
        """Analyze a ZIP archive containing Python source files."""
        # Save and extract ZIP
        zip_path = save_uploaded_file(content, filename, temp_dir)
        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)

        python_files, zip_errors = safe_extract_zip(zip_path, extract_dir)
        result.errors.extend(zip_errors)

        if not python_files:
            result.status = AnalysisStatus.FAILED
            result.errors.append(
                "No Python files found in the uploaded ZIP archive"
            )
            return result

        # Aggregate complexity across all files
        all_complexity = ComplexityResult()

        for file_path in python_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    source_code = f.read()
            except (UnicodeDecodeError, IOError) as e:
                result.errors.append(
                    f"Could not read {os.path.basename(file_path)}: {e}"
                )
                continue

            relative_name = os.path.relpath(file_path, extract_dir)

            # AST parsing
            file_info, ast_findings = self.parser.parse_file(
                source_code, relative_name
            )
            if file_info:
                result.files_analyzed.append(file_info)
            result.findings.extend(ast_findings)

            # Pylint
            try:
                pylint_findings = self.pylint.analyze(
                    file_path, base_dir=extract_dir
                )
                result.findings.extend(pylint_findings)
            except Exception:
                pass

            # Bandit
            try:
                bandit_findings = self.bandit.analyze(
                    file_path, base_dir=extract_dir
                )
                result.findings.extend(bandit_findings)
            except Exception:
                pass

            # Radon
            try:
                complexity_result, radon_findings = self.radon.analyze(
                    file_path, base_dir=extract_dir
                )
                result.findings.extend(radon_findings)
                # Merge complexity
                all_complexity.total_complexity += complexity_result.total_complexity
                all_complexity.functions.extend(complexity_result.functions)
                if complexity_result.raw_metrics:
                    if all_complexity.raw_metrics is None:
                        all_complexity.raw_metrics = {}
                    all_complexity.raw_metrics[relative_name] = (
                        complexity_result.raw_metrics
                    )
            except Exception:
                pass

        # Compute average complexity
        if all_complexity.functions:
            all_complexity.average_complexity = round(
                all_complexity.total_complexity / len(all_complexity.functions), 2
            )
        result.complexity = all_complexity

        # Set tool reports for ZIP analysis
        result.tools_used = ["AST", "Pylint", "Bandit", "Radon"]
        result.tool_reports["AST"] = ToolReport(status=ToolStatus.SUCCESS)
        result.tool_reports["Pylint"] = ToolReport(status=ToolStatus.SUCCESS)
        result.tool_reports["Bandit"] = ToolReport(status=ToolStatus.SUCCESS)
        result.tool_reports["Radon"] = ToolReport(status=ToolStatus.SUCCESS)

        # SonarQube for ZIP
        if self.sonar_enabled:
            try:
                if self.sonarqube.is_available():
                    sonar_findings = self.sonarqube.analyze(
                        extract_dir, base_dir=extract_dir
                    )
                    result.findings.extend(sonar_findings)
                    result.tool_reports["SonarQube"] = ToolReport(
                        status=ToolStatus.SUCCESS,
                        findings_count=len(sonar_findings),
                    )
                    result.tools_used.append("SonarQube")
                else:
                    result.tool_reports["SonarQube"] = ToolReport(
                        status=ToolStatus.UNAVAILABLE,
                        message="SonarQube server is not reachable",
                    )
            except Exception as e:
                result.tool_reports["SonarQube"] = ToolReport(
                    status=ToolStatus.FAILED, message=str(e)
                )
        else:
            result.tool_reports["SonarQube"] = ToolReport(
                status=ToolStatus.SKIPPED,
                message="SonarQube integration is disabled",
            )

        return result

    def get_result(self, analysis_id: str) -> Optional[AnalysisResult]:
        """Retrieve a stored analysis result by ID."""
        return self.storage.load(analysis_id)

    def list_results(self) -> list[str]:
        """List all stored analysis IDs."""
        return self.storage.list_analyses()
