+++
title = 'My First Post'
date = 2024-08-30T16:42:00+02:00
+++


# Hello World

some code:

```python
import requests
try:
    for i in range(1,20):
        r = requests.get(f"https://www.google.de/{i}")
        print(r.text[:20])
except KeyboardInterrupt:
    pass
```
