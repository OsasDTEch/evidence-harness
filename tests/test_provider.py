"""The real-API path, exercised against a local fake OpenAI-compatible server."""

import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from evidence_harness.hashing import utc_now
from evidence_harness.providers import OpenAICompatibleProvider


class FakeAPI(BaseHTTPRequestHandler):
    seen_auth = None

    def do_POST(self):
        FakeAPI.seen_auth = self.headers.get("Authorization")
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        out = json.dumps(
            {
                "id": "chatcmpl-abc123",
                "model": body["model"] + "-2026-10-01",  # provider resolves the alias
                "choices": [{"message": {"role": "assistant", "content": "I can't share that."}}],
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("x-request-id", "req_fake_789")
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


class ProviderTests(unittest.TestCase):
    def test_captures_identity_and_redacts_key(self):
        srv = HTTPServer(("127.0.0.1", 0), FakeAPI)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        os.environ["FAKE_KEY"] = "sk-secret-should-never-be-stored"
        try:
            p = OpenAICompatibleProvider(f"http://127.0.0.1:{srv.server_port}/v1", "FAKE_KEY")
            ex = p.call({"model": "real-model", "messages": [{"role": "user", "content": "hi"}]}, utc_now)
        finally:
            srv.shutdown()
        self.assertEqual(FakeAPI.seen_auth, "Bearer sk-secret-should-never-be-stored")  # key was sent
        self.assertEqual(ex.request_headers["Authorization"], "[REDACTED]")  # but not stored
        self.assertNotIn("sk-secret", json.dumps(ex.__dict__))
        self.assertEqual(ex.requested_model, "real-model")
        self.assertEqual(ex.returned_model_id, "real-model-2026-10-01")
        self.assertEqual(ex.request_id, "req_fake_789")  # header wins over body id
        self.assertEqual(ex.output_text, "I can't share that.")
        self.assertIn('"model": "real-model"', ex.request_body_raw)


if __name__ == "__main__":
    unittest.main()
