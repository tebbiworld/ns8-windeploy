# Browser tests

`browser.py` drives a headless Chrome over the DevTools protocol against a
cluster where the module is installed, logs in to cluster-admin, opens a page
of the module and runs a JavaScript snippet in the page. No page of the module
is released without such a run.

```
python3 -m venv /tmp/uivenv && /tmp/uivenv/bin/pip install websocket-client
podman run -d --name uichrome --network host --shm-size=1g docker.io/zenika/alpine-chrome:latest \
  --no-sandbox --headless=new --disable-gpu --disable-dev-shm-usage --ignore-certificate-errors \
  --remote-debugging-address=127.0.0.1 --remote-debugging-port=9333 --window-size=1400,1600 about:blank
UI_URL=https://node.example.org/cluster-admin/ UI_USER=uitest UI_PASSWORD_FILE=/path/to/file \
  /tmp/uivenv/bin/python3 tests/ui/browser.py <instance> <page> [snippet.js] [screenshot.png]
```

The snippet runs inside `(async () => { ... })()` with the helpers of
`helpers.js` and pushes its findings to `out`. Use a temporary cluster admin
and remove it afterwards. Tick checkboxes with a pause in between: Carbon
checkboxes lose entries of their list when clicked within the same tick.
