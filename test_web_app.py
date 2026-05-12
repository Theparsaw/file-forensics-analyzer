#!/usr/bin/env python3
"""Regression tests for the Flask upload interface."""

from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import static_dynamic_analyzer as analyzer
from web_app import app


class WebAppTests(unittest.TestCase):
    def setUp(self) -> None:
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_analyze_requires_uploaded_files(self) -> None:
        response = self.client.post("/analyze", data={}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertEqual(payload["results"], [])
        self.assertIn("Upload at least one file", payload["error"])

    def test_analyze_handles_multiple_uploaded_files(self) -> None:
        response = self.client.post(
            "/analyze",
            data={
                "files": [
                    (io.BytesIO(b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n"), "invoice.txt"),
                    (io.BytesIO(b"\x89PNG\r\n\x1a\n" + b"\0" * 20), "image.doc"),
                ]
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        results = response.get_json()["results"]
        self.assertEqual(len(results), 2)
        self.assertEqual([result["uploaded_filename"] for result in results], ["invoice.txt", "image.doc"])
        self.assertEqual([result["detected_type"] for result in results], ["pdf", "png"])
        self.assertFalse(results[0]["extension_matches"])
        self.assertFalse(results[1]["extension_matches"])

    def test_web_route_uses_same_analyze_path_as_cli_flow(self) -> None:
        content = b"const url = 'http://example.com';\nconsole.log(url);\n"
        with tempfile.TemporaryDirectory() as tmp:
            direct_path = Path(tmp) / "picture.gif"
            direct_path.write_bytes(content)
            direct_result = analyzer.analyze_path(direct_path)

        with mock.patch("web_app.analyzer.analyze_path", wraps=analyzer.analyze_path) as analyze_path:
            response = self.client.post(
                "/analyze",
                data={"files": [(io.BytesIO(content), "picture.gif")]},
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 200)
        analyze_path.assert_called_once()
        web_result = response.get_json()["results"][0]
        for key in ("detected_type", "description", "extension", "extension_matches", "extension_compatible"):
            self.assertEqual(web_result[key], direct_result[key])


if __name__ == "__main__":
    unittest.main()
