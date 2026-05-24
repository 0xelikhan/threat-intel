# Custom YARA rules

Drop `.yar` or `.yara` rule files in this directory. They get loaded into the
file-scanner ruleset alongside the vendor packs (signature-base, yara-rules,
mandiant-rtc) and re-loaded automatically within 60 seconds of any change
(watchdog).

Validate a candidate rule before saving:

```
POST /api/scan/rules
Body: {"name": "my_rule", "rule": "rule X { strings: $a = \"foo\" condition: $a }"}
```

The endpoint compiles with yara-python and rejects rules that fail to parse.
