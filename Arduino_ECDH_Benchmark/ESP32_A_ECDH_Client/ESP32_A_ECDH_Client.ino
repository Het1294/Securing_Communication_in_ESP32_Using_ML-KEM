
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>
#include <string.h>

const char *AP_SSID = "ESP32-Gateway";
const char *AP_PASS = "SecureIoT123";
IPAddress gatewayIP(192, 168, 4, 1);
const uint16_t TCP_PORT = 5000;

WiFiClient client;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context drbg;

static int rng(void *ctx, unsigned char *buf, size_t len) {
  return mbedtls_ctr_drbg_random(
      (mbedtls_ctr_drbg_context *)ctx, buf, len);
}

bool readExact(uint8_t *buf, size_t len) {
  size_t got = 0;
  uint32_t start = millis();

  while (got < len && millis() - start < 15000) {
    if (!client.connected() && !client.available()) return false;
    int n = client.read(buf + got, len - got);
    if (n > 0) got += n;
    else delay(1);
  }
  return got == len;
}

bool writeExact(const uint8_t *buf, size_t len) {
  size_t sent = 0;
  uint32_t start = millis();

  while (sent < len && millis() - start < 15000) {
    size_t n = client.write(buf + sent, len - sent);
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

  uint8_t salt[32] = {0};

  return mbedtls_hkdf(
      md, salt, sizeof(salt),
      secret, 32,
      (const uint8_t *)info, strlen(info),
      key, 32) == 0;
}

void setup() {
  Serial.begin(115200);
  delay(1500);

  Serial.println("\n=== ESP32-A ECDH-P256 Client ===");

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&drbg);

  const char *pers = "ESP32-ECDH-Client";
  int ret = mbedtls_ctr_drbg_seed(
      &drbg, mbedtls_entropy_func, &entropy,
      (const unsigned char *)pers, strlen(pers));

  if (ret != 0) {
    Serial.printf("RNG seed failed: -0x%04X\n", -ret);
    return;
  }

  WiFi.mode(WIFI_STA);
  WiFi.begin(AP_SSID, AP_PASS);

  Serial.print("Connecting to gateway Wi-Fi");

  uint32_t wifiStart = millis();
  while (WiFi.status() != WL_CONNECTED &&
         millis() - wifiStart < 20000) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Wi-Fi connection failed");
    return;
  }

  Serial.print("Client IP: ");
  Serial.println(WiFi.localIP());

  Serial.println("Connecting to gateway TCP server...");
  if (!client.connect(gatewayIP, TCP_PORT)) {
    Serial.println("TCP connection failed");
    return;
  }

  Serial.println("TCP connected");

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);

  mbedtls_mpi dA, zA;
  mbedtls_ecp_point QA, QB;

  mbedtls_mpi_init(&dA);
  mbedtls_mpi_init(&zA);
  mbedtls_ecp_point_init(&QA);
  mbedtls_ecp_point_init(&QB);

  uint8_t pubA[65], pubB[65];
  uint8_t secret[32], keyA[32], digestA[32], digestB[32];
  size_t pubLen = 0;
  bool success = false;

  uint32_t handshakeStart = millis();

  ret = mbedtls_ecp_group_load(
      &grp, MBEDTLS_ECP_DP_SECP256R1);

  if (ret != 0) {
    Serial.printf("Curve load failed: -0x%04X\n", -ret);
    goto cleanup;
  }

  {
    uint32_t t = micros();
    ret = mbedtls_ecp_gen_keypair(
        &grp, &dA, &QA, rng, &drbg);
    uint32_t elapsed = micros() - t;

    if (ret != 0) {
      Serial.printf("Key generation failed: -0x%04X\n", -ret);
      goto cleanup;
    }

    Serial.printf("A key generation: %.3f ms\n",
                  elapsed / 1000.0);
  }

  ret = mbedtls_ecp_point_write_binary(
      &grp, &QA, MBEDTLS_ECP_PF_UNCOMPRESSED,
      &pubLen, pubA, sizeof(pubA));

  if (ret != 0 || pubLen != 65) {
    Serial.println("Public-key serialization failed");
    goto cleanup;
  }

  // Protocol order: B sends its 65-byte public key first.
  if (!readExact(pubB, sizeof(pubB))) {
    Serial.println("Receiving gateway public key failed");
    goto cleanup;
  }

  ret = mbedtls_ecp_point_read_binary(
      &grp, &QB, pubB, sizeof(pubB));

  if (ret != 0) {
    Serial.printf("Gateway public key invalid: -0x%04X\n", -ret);
    goto cleanup;
  }

  if (!writeExact(pubA, sizeof(pubA))) {
    Serial.println("Sending client public key failed");
    goto cleanup;
  }

  Serial.println("Exchanged 65-byte public keys");

  {
    uint32_t t = micros();
    ret = mbedtls_ecdh_compute_shared(
        &grp, &zA, &QB, &dA, rng, &drbg);
    uint32_t elapsed = micros() - t;

    if (ret != 0) {
      Serial.printf("ECDH failed: -0x%04X\n", -ret);
      goto cleanup;
    }

    Serial.printf("A shared-secret computation: %.3f ms\n",
                  elapsed / 1000.0);
  }

  ret = mbedtls_mpi_write_binary(
      &zA, secret, sizeof(secret));

  if (ret != 0) {
    Serial.println("Shared-secret export failed");
    goto cleanup;
  }

  {
    uint32_t t = micros();
    bool ok = deriveKey(secret, keyA);
    uint32_t elapsed = micros() - t;

    if (!ok) {
      Serial.println("HKDF failed");
      goto cleanup;
    }

    Serial.printf("A HKDF-SHA256: %.3f ms\n",
                  elapsed / 1000.0);
  }

  ret = mbedtls_md(
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
      keyA, sizeof(keyA), digestA);

  if (ret != 0) {
    Serial.println("Fingerprint calculation failed");
    goto cleanup;
  }

  if (!readExact(digestB, sizeof(digestB))) {
    Serial.println("Receiving gateway fingerprint failed");
    goto cleanup;
  }

  if (memcmp(digestA, digestB, sizeof(digestA)) != 0) {
    Serial.println("SESSION KEY AGREEMENT: FAIL");
    goto cleanup;
  }

  Serial.println("SESSION KEY AGREEMENT: PASS");
  Serial.println("ECDH-P256 + HKDF-SHA256 complete");
  Serial.println("Session key: 256 bits");

  Serial.printf("Handshake elapsed on A: %lu ms\n",
                (unsigned long)(millis() - handshakeStart));
  Serial.println("Note: unauthenticated benchmark only");

  success = true;

cleanup:
  if (!success) Serial.println("Handshake failed");

  client.stop();
  mbedtls_ecp_point_free(&QA);
  mbedtls_ecp_point_free(&QB);
  mbedtls_mpi_free(&dA);
  mbedtls_mpi_free(&zA);
  mbedtls_ecp_group_free(&grp);
}

void loop() {
  delay(10000);
}
