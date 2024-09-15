
Start debugging server
```
PYGTCHA_SALT=foobar gunicorn pygtcha.pygtcha:app --bind localhost:8000 --worker-class aiohttp.GunicornWebWorker --reload
```
