
#include <Arduino.h>
#include <esp_system.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/version.h>

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context drbg;

static int rng(void *ctx, unsigned char *buf, size_t len) {
  return mbedtls_ctr_drbg_random(
      (mbedtls_ctr_drbg_context *)ctx, buf, len);
}

void setup() {
  Serial.begin(115200);
  delay(1500);

  Serial.println("\n=== ESP32 ECDH-P256 Benchmark ===");

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&drbg);

  const char *personalization = "ESP32-ECDH-Benchmark";
  int ret = mbedtls_ctr_drbg_seed(
      &drbg, mbedtls_entropy_func, &entropy,
      (const unsigned char *)personalization,
      strlen(personalization));

  if (ret != 0) {
    Serial.printf("DRBG seed failed: -0x%04X\n", -ret);
    return;
  }

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);

  ret = mbedtls_ecp_group_load(
      &grp, MBEDTLS_ECP_DP_SECP256R1);

  if (ret != 0) {
    Serial.printf("Curve load failed: -0x%04X\n", -ret);
    mbedtls_ecp_group_free(&grp);
    return;
  }

  mbedtls_mpi dA, dB, zA, zB;
  mbedtls_ecp_point QA, QB;

  mbedtls_mpi_init(&dA);
  mbedtls_mpi_init(&dB);
  mbedtls_mpi_init(&zA);
  mbedtls_mpi_init(&zB);
  mbedtls_ecp_point_init(&QA);
  mbedtls_ecp_point_init(&QB);

  uint32_t start, end;

  // Generate keypair A
  start = micros();
  ret = mbedtls_ecp_gen_keypair(
      &grp, &dA, &QA, rng, &drbg);
  end = micros();

  if (ret != 0) {
    Serial.printf("Keypair A failed: -0x%04X\n", -ret);
    goto cleanup;
  }
  Serial.printf("Keypair A generation: %.3f ms\n",
                (end - start) / 1000.0);

  // Generate keypair B
  start = micros();
  ret = mbedtls_ecp_gen_keypair(
      &grp, &dB, &QB, rng, &drbg);
  end = micros();

  if (ret != 0) {
    Serial.printf("Keypair B failed: -0x%04X\n", -ret);
    goto cleanup;
  }
  Serial.printf("Keypair B generation: %.3f ms\n",
                (end - start) / 1000.0);

  // A computes shared secret using B's public key
  start = micros();
  ret = mbedtls_ecdh_compute_shared(
      &grp, &zA, &QB, &dA, rng, &drbg);
  end = micros();

  if (ret != 0) {
    Serial.printf("A shared-secret calculation failed: -0x%04X\n",
                  -ret);
    goto cleanup;
  }
  Serial.printf("A shared-secret computation: %.3f ms\n",
                (end - start) / 1000.0);

  // B computes shared secret using A's public key
  start = micros();
  ret = mbedtls_ecdh_compute_shared(
      &grp, &zB, &QA, &dB, rng, &drbg);
  end = micros();

  if (ret != 0) {
    Serial.printf("B shared-secret calculation failed: -0x%04X\n",
                  -ret);
    goto cleanup;
  }
  Serial.printf("B shared-secret computation: %.3f ms\n",
                (end - start) / 1000.0);

  if (mbedtls_mpi_cmp_mpi(&zA, &zB) == 0) {
    Serial.println("Shared-secret agreement: PASS");
  } else {
    Serial.println("Shared-secret agreement: FAIL");
  }

  Serial.println("Curve: secp256r1 (NIST P-256)");
  Serial.println("Note: This is a local computation benchmark.");
  Serial.println("It excludes Wi-Fi, network exchange and HKDF.");

cleanup:
  mbedtls_ecp_point_free(&QA);
  mbedtls_ecp_point_free(&QB);
  mbedtls_mpi_free(&dA);
  mbedtls_mpi_free(&dB);
  mbedtls_mpi_free(&zA);
  mbedtls_mpi_free(&zB);
  mbedtls_ecp_group_free(&grp);
}

void loop() {
  delay(10000);
}
