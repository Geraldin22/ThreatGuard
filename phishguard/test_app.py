import os, tempfile
os.environ["PHISHGUARD_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ["PHISHGUARD_TOKEN"] = "secret"
import app as A

c = A.app.test_client()
H = {"X-API-Key": "secret"}

def test_auth():
    assert c.get("/api/state").status_code == 401
    assert c.get("/api/state", headers={"X-API-Key": "nope"}).status_code == 401
    assert c.get("/api/state", headers=H).status_code == 200
    assert c.get("/").status_code == 200
    assert c.get("/share?text=hi").status_code == 200
    assert c.get("/manifest.webmanifest").status_code == 200

def test_access_gate():
    r = c.post("/api/messages", json={"body": "hi"}, headers=H)
    assert r.status_code == 403
    assert c.post("/api/access", json={"allowed": True}, headers=H).get_json()["access"] is True

def test_detection_and_persistence():
    phish = "URGENT: Your bank account has been suspended. Verify your password immediately at http://secure-bank-login.example.com"
    r = c.post("/api/messages", json={"sender": "SecureBank", "channel": "SMS", "body": phish}, headers=H)
    d = r.get_json()
    assert r.status_code == 201 and d["level"] == "high" and d["threat_type"] == "Smishing" and d["status"] == "Blocked"
    assert any(x["type"] == "link" for x in d["ranges"])
    safe = c.post("/api/messages", json={"sender": "Lucas", "channel": "SMS", "body": "lunch at 12:30 tomorrow?"}, headers=H).get_json()
    assert safe["level"] == "low" and safe["status"] == "Allowed"
    ip = c.post("/api/messages", json={"body": "Action required: log in now at http://192.168.44.12/mail-reset"}, headers=H).get_json()
    assert ip["level"] == "high"
    s = c.get("/api/stats", headers=H).get_json()
    assert s == {"total": 3, "high": 2, "clean": 1}
    assert len(c.get("/api/messages", headers=H).get_json()["messages"]) == 3

def test_validation_and_xss_safe_storage():
    assert c.post("/api/messages", json={"body": "  "}, headers=H).status_code == 400
    assert c.post("/api/scan", json={}, headers=H).status_code == 400
    m = c.post("/api/scan", json={"body": "<script>alert(1)</script> 😀 verify http://x.com"}, headers=H).get_json()
    assert m["channel"] == "Manual"
    # ranges are UTF-16 aligned: emoji counts as 2 units
    link = [r for r in m["ranges"] if r["type"] == "link"][0]
    units = m["body"].encode("utf-16-le")
    assert units[link["start"]*2:link["end"]*2].decode("utf-16-le").startswith("http://x.com")

def test_clear_and_revoke():
    c.post("/api/inbox/clear", headers=H)
    msgs = c.get("/api/messages", headers=H).get_json()["messages"]
    assert all(m["archived"] for m in msgs if m["channel"] != "Manual")
    assert c.get("/api/stats", headers=H).get_json()["total"] == 4   # stats keep history
    c.post("/api/access", json={"allowed": False}, headers=H)
    assert c.post("/api/messages", json={"body": "x"}, headers=H).status_code == 403
    assert c.post("/api/scan", json={"body": "x"}, headers=H).status_code == 201  # manual scan always works
