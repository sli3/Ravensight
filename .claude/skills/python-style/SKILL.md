---
name: python-style
description: Python coding standards for this project. Apply automatically whenever writing a new Python file, editing an existing .py file, or reviewing code in code-sanity-check.
paths: "**/*.py"
---

## Python Style Guide

### Standards

#### Imports
Group imports in this order, separated by blank lines:
```python
# 1. Standard library
import logging
from pathlib import Path

# 2. Third-party
import requests
from openai import OpenAI

# 3. Local modules
from ravensight.wazuh_client import WazuhClient
```

---

#### Type Hints
Always annotate function signatures:
```python
# Correct
def fetch_alerts(hours: int, level: int = 7) -> list[dict]:

# Wrong
def fetch_alerts(hours, level=7):
```

---

#### Docstrings
One line is enough. Always present on every function and class:
```python
def fetch_alerts(hours: int) -> list[dict]:
    """Fetch Wazuh alerts from the last N hours."""
```

---

#### Logging
Always use `logging`, never `print`:
```python
# Correct
logger = logging.getLogger(__name__)
logger.info("Fetching alerts from Wazuh...")
logger.error("Connection failed: %s", err)

# Wrong
print("Fetching alerts...")
```

---

#### Exception Handling
Always catch specific exceptions. Never use bare `except:`:
```python
# Correct
try:
    response = requests.get(url, timeout=30)
    response.raise_for_status()
except requests.exceptions.Timeout:
    logger.error("Wazuh API timed out")
    raise
except requests.exceptions.HTTPError as err:
    logger.error("HTTP error: %s", err)
    raise

# Wrong
try:
    response = requests.get(url)
except:
    pass
```

---

#### File Paths
Always use `pathlib.Path`, never `os.path`:
```python
# Correct
from pathlib import Path
baseline_path = Path(config["baseline"]["store_path"])
baseline_path.parent.mkdir(parents=True, exist_ok=True)

# Wrong
import os
baseline_path = os.path.join(config["baseline"]["store_path"])
```

---

#### Constants and Config
Never hardcode credentials, IPs, or paths. Always read from config:
```python
# Correct
base_url = config["llm"]["base_url"]

# Wrong
base_url = "http://192.168.1.100:8080/v1"
```

---

#### File Header Template
Every new module should begin with:
```python
"""
[module_name].py — [One line description]
"""
import logging

logger = logging.getLogger(__name__)
```

---

### Rules

- Never use `print()` — always `logging`
- Never use bare `except:`
- Never use `os.path` — always `pathlib.Path`
- Never hardcode credentials or IPs
- Always add type hints to function signatures
- Always add a docstring to every function and class
