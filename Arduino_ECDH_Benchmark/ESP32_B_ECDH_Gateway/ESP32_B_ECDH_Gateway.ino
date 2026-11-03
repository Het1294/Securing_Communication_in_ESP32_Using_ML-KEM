#include <mbedtls/hkdf.h>
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiServer.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>
#include <mbedtls/version.h>
#include <string.h>

const char *AP_SSID = "ESP32-Gateway";
const char *AP_PASS = "SecureIoT123";
const uint16_t TCP_PORT = 5000;

WiFiServer server(TCP_PORT);
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context drbg;

static int rng(void *ctx, unsigned char *buf, size_t len) {
  return mbedtls_ctr_drbg_random(
      (mbedtls_ctr_drbg_context *)ctx, buf, len);
}

bool readExact(WiFiClient &c, uint8_t *buf, size_t len) {
  size_t got = 0;
  uint32_t start = millis();

  while (got < len && millis() - start < 15000) {
    if (!c.connected() && !c.available()) return false;
    int n = c.read(buf + got, len - got);
    if (n > 0) got += n;
    else delay(1);
  }
  return got == len;
}

bool writeExact(WiFiClient &c, const uint8_t *buf, size_t len) {
  size_t sent = 0;
  uint32_t start = millis();

  while (sent < len && millis() - start < 15000) {
    size_t n = c.write(buf + sent, len - sent);
    if (n > 0) sent += n;
    else delay(1);
  }
  return sent == len;
}

bool deriveKey(const uint8_t *secret, uint8_t *key) {
  const char *info = "SecureIoT-ECDH-AES256GCM-v1";
  const mbedtls_md_info_t *md =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  if (!md) return false;

  // HKDF-SHA256 with a 32-byte all-zero salt.
  uint8_t salt[32] = {0};
  return mbedtls_hkdf(md, salt, sizeof(salt),
                      secret, 32,
                      (const uint8_t *)info, strlen(info),
                      key, 32) == 0;
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n=== ESP32-B ECDH-P256 Gateway ===");

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&drbg);

  const char *pers = "ESP32-ECDH-Gateway";
  int ret = mbedtls_ctr_drbg_seed(
      &drbg, mbedtls_entropy_func, &entropy,
      (const unsigned char *)pers, strlen(pers));

  if (ret != 0) {
    Serial.printf("RNG seed failed: -0x%04X\n", -ret);
    return;
  }

  WiFi.mode(WIFI_AP);
  if (!WiFi.softAP(AP_SSID, AP_PASS)) {
    Serial.println("Wi-Fi AP start failed");
    return;
  }

  Serial.print("Gateway IP: ");
  Serial.println(WiFi.softAPIP());

  server.begin();
  Serial.printf("TCP server listening on port %u\n", TCP_PORT);
  Serial.println("Waiting for ESP32-A...");
}

void loop() {
  WiFiClient client = server.accept();
  if (!client) {
    delay(10);
    return;
  }

  Serial.println("\nESP32-A connected");

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);

  mbedtls_mpi dB, zB;
  mbedtls_ecp_point QB, QA;
  mbedtls_mpi_init(&dB);
  mbedtls_mpi_init(&zB);
  mbedtls_ecp_point_init(&QB);
  mbedtls_ecp_point_init(&QA);

  uint8_t pubB[65], pubA[65];
  uint8_t secret[32], keyB[32], digestB[32];
  size_t pubLen = 0;

  bool success = false;
  uint32_t handshakeStart = millis();

  ret:
  int rc = mbedtls_ecp_group_load(
      &grp, MBEDTLS_ECP_DP_SECP256R1);
  if (rc != 0) {
    Serial.printf("Curve load failed: -0x%04X\n", -rc);
    goto cleanup;
  }

  {
    uint32_t t = micros();
    rc = mbedtls_ecp_gen_keypair(&grp, &dB, &QB, rng, &drbg);
    uint32_t elapsed = micros() - t;
    if (rc != 0) {
      Serial.printf("Key generation failed: -0x%04X\n", -rc);
      goto cleanup;
    }
    Serial.printf("B key generation: %.3f ms\n", elapsed / 1000.0);
  }

  rc = mbedtls_ecp_point_write_binary(
      &grp, &QB, MBEDTLS_ECP_PF_UNCOMPRESSED,
      &pubLen, pubB, sizeof(pubB));
  if (rc != 0 || pubLen != 65) {
    Serial.println("Public-key serialization failed");
    goto cleanup;
  }

  if (!writeExact(client, pubB, sizeof(pubB)) ||
      !readExact(client, pubA, sizeof(pubA))) {
    Serial.println("Public-key exchange failed");
    goto cleanup;
  }

  rc = mbedtls_ecp_point_read_binary(
      &grp, &QA, pubA, sizeof(pubA));
  if (rc != 0) {
    Serial.printf("Peer public key invalid: -0x%04X\n", -rc);
    goto cleanup;
  }

  {
    uint32_t t = micros();
    rc = mbedtls_ecdh_compute_shared(
        &grp, &zB, &QA, &dB, rng, &drbg);
    uint32_t elapsed = micros() - t;
    if (rc != 0) {
      Serial.printf("ECDH failed: -0x%04X\n", -rc);
      goto cleanup;
    }
    Serial.printf("B shared-secret computation: %.3f ms\n",
                  elapsed / 1000.0);
  }

  rc = mbedtls_mpi_write_binary(&zB, secret, sizeof(secret));
  if (rc != 0) {
    Serial.println("Shared-secret export failed");
    goto cleanup;
  }

  {
    uint32_t t = micros();
    bool ok = deriveKey(secret, keyB);
    uint32_t elapsed = micros() - t;
    if (!ok) {
      Serial.println("HKDF failed");
      goto cleanup;
    }
    Serial.printf("B HKDF-SHA256: %.3f ms\n", elapsed / 1000.0);
  }

  rc = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                  keyB, sizeof(keyB), digestB);
  if (rc != 0) {
    Serial.println("Fingerprint calculation failed");
    goto cleanup;
  }

  if (!writeExact(client, digestB, sizeof(digestB))) {
    Serial.println("Fingerprint send failed");
    goto cleanup;
  }

  {
    uint32_t elapsed = millis() - handshakeStart;
    Serial.printf("Handshake elapsed on B: %lu ms\n",
                  (unsigned long)elapsed);
  }

  Serial.println("ECDH/HKDF handshake: COMPLETE");
  Serial.println("Key fingerprint sent to A for verification");
  Serial.println("Note: unauthenticated benchmark only");
  success = true;

cleanup:
  if (!success) Serial.println("Handshake failed");
  client.stop();
  mbedtls_ecp_point_free(&QB);
  mbedtls_ecp_point_free(&QA);
  mbedtls_mpi_free(&dB);
  mbedtls_mpi_free(&zB);
  mbedtls_ecp_group_free(&grp);
  delay(100);
}
