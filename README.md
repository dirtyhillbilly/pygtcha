
Start debugging server
```
PYGTCHA_CONFIG=doc/pygtcha.yml gunicorn pygtcha.pygtcha:app --bind localhost:8000 --worker-class aiohttp.GunicornWebWorker --reload
```
