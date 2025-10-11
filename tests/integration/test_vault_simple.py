#!/usr/bin/env python
"""
Simple integration test for Vault container setup
"""

from vault_test_base import VaultTestBase


class VaultSimpleIntegrationTest(VaultTestBase):
    """Simple integration test to verify Vault container setup"""

    def test_vault_connection(self):
        """Test basic Vault connection"""
        response = self._vault_request("GET", "sys/health")
        self.assertEqual(response.status_code, 200)

        health_data = response.json()
        self.assertTrue(health_data["initialized"])
        self.assertFalse(health_data["sealed"])

    def test_vault_authentication(self):
        """Test Vault authentication with root token"""
        response = self._vault_request("GET", "auth/token/lookup-self")
        self.assertEqual(response.status_code, 200)

        token_data = response.json()
        self.assertEqual(token_data["data"]["id"], self.vault_token)

    def test_vault_kv_store(self):
        """Test basic KV store functionality"""
        # Store a test secret
        test_data = {"test_key": "test_value", "number": "42"}
        response = self._vault_request(
            "PUT", "secret/data/test/simple", {"data": test_data}
        )
        self.assertIn(response.status_code, [200, 204])

        # Retrieve the secret
        response = self._vault_request("GET", "secret/data/test/simple")
        self.assertEqual(response.status_code, 200)

        retrieved_data = response.json()["data"]["data"]
        self.assertEqual(retrieved_data["test_key"], "test_value")
        self.assertEqual(retrieved_data["number"], "42")

    def test_vault_secret_paths(self):
        """Test that we can create secrets in different paths"""
        # Test hub path
        hub_data = {"username": "hub-user", "password": "hub-pass"}
        response = self._vault_request(
            "PUT", "secret/data/hub/test-secret", {"data": hub_data}
        )
        self.assertIn(response.status_code, [200, 204])

        # Test spoke path
        spoke_data = {"username": "spoke-user", "password": "spoke-pass"}
        response = self._vault_request(
            "PUT", "secret/data/test-spoke/test-secret", {"data": spoke_data}
        )
        self.assertIn(response.status_code, [200, 204])

        # Verify we can retrieve from both paths
        response = self._vault_request("GET", "secret/data/hub/test-secret")
        self.assertEqual(response.status_code, 200)
        hub_retrieved = response.json()["data"]["data"]
        self.assertEqual(hub_retrieved["username"], "hub-user")

        response = self._vault_request("GET", "secret/data/test-spoke/test-secret")
        self.assertEqual(response.status_code, 200)
        spoke_retrieved = response.json()["data"]["data"]
        self.assertEqual(spoke_retrieved["username"], "spoke-user")


if __name__ == "__main__":
    import unittest

    VaultTestBase.check_podman_availability()
    unittest.main(verbosity=2)
