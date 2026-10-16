---
id: requests-major-version
title: The requests library is on major version 2
domain: python
author: human-jonny
status: accepted
confidence: high
updated: 2026-10-17
sources: [https://pypi.org/project/requests/]
tags: [python, dependencies, example]
---

# The requests library is on major version 2

The latest release of `requests` on PyPI is a 2.x version, so code written against the 2.x API works with the newest release.

If this entry drifts, a 3.x release has shipped. Check the changelog for breaking changes before upgrading.

```deltar-check
{"type": "http_json", "url": "https://pypi.org/pypi/requests/json", "path": "info.version", "op": "matches", "value": "^2\\.", "half_life_days": 14}
```
