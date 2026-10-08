"""Python AST-based parser for extracting structural information."""

import ast
from typing import Optional
from app.models.analysis import FileInfo
from app.models.finding import Finding, FindingType, Severity


class PythonParser:
    """Parse Python source code using the ast module."""

    def parse_file(self, source_code: str, filename: str) -> tuple[Optional[FileInfo], list[Finding]]:
        """
        Parse Python source code and extract structural information.

        Args:
            source_code: The Python source code string.
            filename: Name of the file being parsed.

        Returns:
            Tuple of (FileInfo or None, list of findings).
            If parsing fails due to syntax errors, FileInfo will have
            has_syntax_errors=True and a syntax-error finding is returned.
        """
        findings: list[Finding] = []
        lines = source_code.splitlines()
        line_count = len(lines)

        try:
            tree = ast.parse(source_code, filename=filename)
        except SyntaxError as e:
            file_info = FileInfo(
                filename=filename,
                language="python",
                lines=line_count,
                has_syntax_errors=True,
                syntax_error_message=str(e),
            )
            finding = Finding(
                id=f"ast_syntax_{filename}_{e.lineno or 0}",
                source="AST",
                type=FindingType.SYNTAX_ERROR,
                severity=Severity.CRITICAL,
                rule="syntax-error",
                message=f"Syntax error: {e.msg}",
                file=filename,
                line=e.lineno or 1,
                column=e.offset,
                evidence=e.text.strip() if e.text else None,
            )
            findings.append(finding)
            return file_info, findings

        # Extract structural information from the AST
        classes = []
        functions = []
        imports = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                classes.append(node.name)
            elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                functions.append(node.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports.append(f"{module}.{alias.name}")

        file_info = FileInfo(
            filename=filename,
            language="python",
            lines=line_count,
            classes=classes,
            functions=functions,
            imports=imports,
            has_syntax_errors=False,
        )

        return file_info, findings

    def is_valid_python(self, source_code: str) -> bool:
        """Check if the source code is syntactically valid Python."""
        try:
            ast.parse(source_code)
            return True
        except SyntaxError:
            return False
