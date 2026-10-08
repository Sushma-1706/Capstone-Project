# Risk-Adaptive Prioritization Engine

Validates raw findings from static analyzers and review agents, merges reports
for the same rule and source location, calculates weighted risk scores, and
returns deterministically ranked JSON.

## Setup

From this directory, install dependencies with:

```sh
python -m pip install -r requirements.txt
```

## Input and output

The command reads a JSON array from standard input. Each finding must include
`agent_id`, `rule_id`, `title`, `file_path`, `line_number`, `severity`, and
`confidence`. Impact metrics are optional and default to `1.0`; each must be
between `1.0` and `10.0` when supplied. Confidence must be between `0.0` and
`1.0`.

```sh
python main.py < findings.json
```

Reports with the same file path, line number, and rule ID are merged. The
highest-confidence report supplies the title and raw severity, while maximum
confidence and impact values are retained. Output risk categories are the
plain tier names `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW`, suitable for
downstream processing. Invalid JSON or findings are reported to stderr and
exit with status 2.

Weights and tier thresholds are configured in
[`config/risk_weights.json`](config/risk_weights.json). The default configuration
is resolved relative to the package, so the pipeline works regardless of the
current working directory.

## Run tests

```sh
python -m unittest discover -s tests -v
```
