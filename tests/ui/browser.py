#!/usr/bin/env python3

#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Open a page of the module in a headless Chrome and run a snippet in it.
See README.md. Prints the findings of the snippet, the requests the page
sent and the errors of the browser console."""

import base64
import json
import os
import sys
import time
import urllib.request

import websocket

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.environ["UI_URL"]
USER = os.environ["UI_USER"]
PASSWORD = open(os.environ["UI_PASSWORD_FILE"]).read()
DEBUG = os.environ.get("UI_CHROME", "http://127.0.0.1:9333")
instance, page = sys.argv[1], sys.argv[2]
snippet = open(sys.argv[3]).read() if len(sys.argv) > 3 and sys.argv[3] else ""
shot = sys.argv[4] if len(sys.argv) > 4 else ""

tabs = json.load(urllib.request.urlopen(DEBUG + "/json"))
ws = websocket.create_connection([t for t in tabs if t["type"] == "page"][0]["webSocketDebuggerUrl"],
                                 timeout=120, suppress_origin=True)
count = 0
logs = []
contexts = {}


def event(m):
    method, p = m.get("method"), m.get("params", {})
    if method == "Runtime.executionContextCreated":
        aux = p["context"].get("auxData", {})
        if aux.get("isDefault"):
            contexts[aux.get("frameId")] = p["context"]["id"]
    elif method == "Runtime.exceptionThrown":
        d = p["exceptionDetails"]
        logs.append("EXCEPTION " + (d.get("exception", {}).get("description") or d.get("text", ""))[:400])
    elif method == "Runtime.consoleAPICalled" and p["type"] == "error":
        logs.append("CONSOLE " + " ".join(str(a.get("value", a.get("description", "")))[:300] for a in p["args"]))
    elif method == "Network.requestWillBeSent" and p["request"]["method"] == "POST":
        body = p["request"].get("postData") or ""
        try:
            data = json.loads(body)
            # never print credentials
            shown = {k: ("***" if "password" in k else v) for k, v in data.get("data", {}).items()}
            logs.append("POST %s %s" % (data.get("action"), json.dumps(shown)[:200]))
        except ValueError:
            pass


def cmd(method, **params):
    global count
    count += 1
    ws.send(json.dumps({"id": count, "method": method, "params": params}))
    while True:
        m = json.loads(ws.recv())
        if m.get("id") == count:
            return m.get("result", {})
        event(m)


def wait(seconds):
    end = time.time() + seconds
    ws.settimeout(1)
    while time.time() < end:
        try:
            event(json.loads(ws.recv()))
        except Exception:
            pass
    ws.settimeout(120)


def js(expression, context=None):
    p = {"expression": expression, "awaitPromise": True, "returnByValue": True}
    if context:
        p["contextId"] = context
    return cmd("Runtime.evaluate", **p).get("result", {}).get("value")


for domain in ("Runtime", "Page", "Network"):
    cmd(domain + ".enable")
cmd("Page.navigate", url=BASE)
wait(15)
FILL = ("const set=(el,v)=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el,v);"
        "el.dispatchEvent(new Event('input',{bubbles:true}));};"
        "const go=()=>[...document.querySelectorAll('button.login-button')].filter(b=>b.offsetParent).pop();")
js("(()=>{" + FILL + "set([...document.querySelectorAll('input')].find(x=>x.type==='text'&&x.offsetParent),%s);go().click();})()"
   % json.dumps(USER))
wait(4)
js("(()=>{" + FILL + "set(document.querySelector('input[type=password]'),%s);go().click();})()" % json.dumps(PASSWORD))
wait(10)
logs.clear()
js("location.hash='#/apps/%s?page=%s'" % (instance, page))
wait(15)
frames = cmd("Page.getFrameTree")["frameTree"].get("childFrames", [])
if not frames:
    print("NO FRAME: login failed or the app did not load")
    sys.exit(1)
ctx = contexts[frames[0]["frame"]["id"]]
if snippet:
    helpers = open(os.path.join(HERE, "helpers.js")).read()
    print(js("(async()=>{%s const out=[]; try{ %s }catch(e){out.push('EXCEPTION '+e.message)} return out.join('\\n');})()"
             % (helpers, snippet), ctx))
    wait(2)
else:
    print((js("document.body.innerText", ctx) or "")[:3000])
if shot:
    open(shot, "wb").write(base64.b64decode(cmd("Page.captureScreenshot", format="png")["data"]))
print("--- requests and errors")
for line in dict.fromkeys(logs):
    if "get-name" not in line:
        print(line)
