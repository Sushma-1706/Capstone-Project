# Static Analysis Engine

A FastAPI-based reusable backend service that accepts Python source code, analyzes it using multiple static analysis tools, and produces structured findings optimized for AI agents.

## Supported Analysis Tools

* **Python AST**: Validates syntax, extracts basic structure (classes, functions, imports)
* **Pylint**: Detects bugs, code smells, coding standard violations, etc.
* **Bandit**: Discovers Python-specific security vulnerabilities.
* **Radon**: Calculates cyclomatic complexity, maintainability index, and raw metrics.
* **SonarQube** (Optional): Provides comprehensive code quality analysis if a server is available.

## Installation

1. Clone or navigate to the module directory.
2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration (Optional)

You can customize behavior by creating a `.env` file from the example:

```bash
cp .env.example .env
```

If you have a local SonarQube instance running, set `SONARQUBE_ENABLED=true` and update the URL/Token in the `.env` file.

## Running the API

Start the FastAPI application with Uvicorn:

```bash
uvicorn app.main:app --reload
```

The service will be available at `http://localhost:8000`.

### API Documentation (Swagger)

A fully interactive Swagger UI is available at:
```
http://localhost:8000/docs
```

## Endpoints

### 1. Health Check
`GET /health`
Returns the status of the service and the availability of the analysis tools.

### 2. Analyze Source Code
`POST /analyze`
Accepts a single `file` parameter (multipart/form-data). The file can be:
- A single Python file (`.py`)
- A ZIP archive (`.zip`) containing a project with Python files

This endpoint returns a comprehensive `AnalysisResult` in JSON, combining findings from AST, Pylint, Bandit, Radon, and optionally SonarQube.

### 3. Get Analysis Results
`GET /results/{analysis_id}`
Retrieves a previously computed analysis by its unique ID.

### 4. List All Analyses
`GET /results`
Returns a list of all analysis IDs currently stored on disk.

## Security Considerations

This module explicitly implements several security safeguards since uploaded code is inherently untrusted:
- Code is **never executed**, only parsed and statically analyzed.
- Subprocess tools (`pylint`, `bandit`, `radon`, `sonar-scanner`) are executed securely (without `shell=True`).
- Zip files are strictly validated against Zip Bombs and Path Traversal attacks during extraction.
- Strict upload size limits are enforced.

## Future AI Integration

The JSON findings produced by this module follow a unified schema `Finding` containing:
- `id`: precise finding identifier
- `source`: the tool that generated it (Pylint, Bandit, etc.)
- `type`: normalized categorized (BUG, CODE_SMELL, SECURITY_VULNERABILITY, etc.)
- `severity`: normalized severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- `rule`: specific tool rule code
- `message`: human-readable description
- `file`, `line`, `column`, `evidence`

This structured format guarantees that external verification agents can programmatically align these static findings with AI-generated reasoning.
