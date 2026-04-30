# coverage-reporter.py

Reads all Sigma rules in the [detection-rules](https://github.com/YOUR-USERNAME/detection-rules) repo and outputs a MITRE ATT&CK coverage matrix — which tactics and techniques are covered, rule counts by severity, and gaps with no detection.

Run weekly and commit the output to track coverage improvement over time.

## Usage
```bash
# Run from the root of the detection-rules repo
python3 coverage_reporter.py

# Output saved to coverage-report.txt by default
python3 coverage_reporter.py --output coverage-report.txt
```

## Sample output
```
MITRE ATT&CK COVERAGE REPORT — 2026-06-01
Total rules: 17

COVERED TACTICS
  Initial Access       2 rules  T1566.001, T1078
  Execution            3 rules  T1059.001, T1059.003, T1204
  Persistence          2 rules  T1547.001, T1053.005
  Privilege Escalation 2 rules  T1055, T1068
  Defense Evasion      2 rules  T1562.001, T1070.001
  Discovery            2 rules  T1082, T1083
  Lateral Movement     2 rules  T1021.002, T1550.002
  Command and Control  2 rules  T1071.004, T1095

GAPS (no coverage)
  Collection           0 rules
  Exfiltration         0 rules
  Impact               0 rules
```

## Requirements
```
PyYAML>=6.0
```

## Screenshots
<!-- Add after build -->
![coverage-reporter output showing MITRE matrix](screenshots/coverage-report-output.png)
