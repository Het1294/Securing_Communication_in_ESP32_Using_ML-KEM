#include <WiFi.h>
#include "DHT.h"
#include "mbedtls/gcm.h"
#include "esp_system.h"

#define DHTPIN 4
#define DHTTYPE DHT22

const char* ssid = "ESP32-Gateway";
const char* password = "SecureIoT123";

const char* serverIP = "192.168.4.1";
const uint16_t serverPort = 5000;

DHT dht(DHTPIN, DHTTYPE);
WiFiClient client;

// TEMPORARY TEST KEY ONLY
// This will later be replaced by ML-KEM + HKDF.
const unsigned char AES_KEY[32] = {
  0x60, 0x3d, 0xeb, 0x10,
  0x15, 0xca, 0x71, 0xbe,
  0x2b, 0x73, 0xae, 0xf0,
  0x85, 0x7d, 0x77, 0x81,
  0x1f, 0x35, 0x2c, 0x07,
  0x3b, 0x61, 0x08, 0xd7,
  0x2d, 0x98, 0x10, 0xa3,
  0x09, 0x14, 0xdf, 0xf4
};

const size_t IV_SIZE = 12;
const size_t TAG_SIZE = 16;

String bytesToHex(const unsigned char* data, size_t len) {

  const char hex[] = "0123456789ABCDEF";

  String result;

  for (size_t i = 0; i < len; i++) {
    result += hex[(data[i] >> 4) & 0x0F];
    result += hex[data[i] & 0x0F];
  }

  return result;
}

void connectToWiFi() {

  Serial.print("Connecting to Gateway");

  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println();
  Serial.println("Wi-Fi connected!");

  Serial.print("ESP32-A IP: ");
  Serial.println(WiFi.localIP());

  Serial.print("Gateway IP: ");
  Serial.println(WiFi.gatewayIP());
}

bool connectToTCP() {

  Serial.println("Connecting to TCP server...");

  if (client.connect(serverIP, serverPort)) {

    Serial.println("TCP connection established!");

    return true;
  }

  Serial.println("TCP connection failed!");

  return false;
}

void setup() {

  Serial.begin(115200);

  delay(1000);

  Serial.println();
  Serial.println("================================");
  Serial.println("ESP32-A SECURE SENSOR NODE");
  Serial.println("================================");

  dht.begin();

  connectToWiFi();

  connectToTCP();
}

void loop() {

  if (WiFi.status() != WL_CONNECTED) {

    Serial.println("Wi-Fi disconnected.");

    connectToWiFi();
  }

  if (!client.connected()) {

    Serial.println("TCP disconnected.");

    client.stop();

    connectToTCP();
  }

  float humidity = dht.readHumidity();
  float temperature = dht.readTemperature();

  if (isnan(humidity) || isnan(temperature)) {

    Serial.println("DHT22 read failed!");

    delay(2000);

    return;
  }

  // Create sensor message
  String plaintext =
    "Temperature=" +
    String(temperature, 2) +
    ",Humidity=" +
    String(humidity, 2);

  Serial.println();
  Serial.print("Sensor data: ");
  Serial.println(plaintext);

  size_t plaintextLen = plaintext.length();

  unsigned char nonce[IV_SIZE];
  unsigned char ciphertext[128];
  unsigned char tag[TAG_SIZE];

  // Generate a NEW random nonce for every packet.
  esp_fill_random(nonce, IV_SIZE);

  mbedtls_gcm_context gcm;

  mbedtls_gcm_init(&gcm);

  // Configure AES-256
  int result = mbedtls_gcm_setkey(
    &gcm,
    MBEDTLS_CIPHER_ID_AES,
    AES_KEY,
    256
  );

  if (result != 0) {

    Serial.println("ERROR: AES key setup failed");

    mbedtls_gcm_free(&gcm);

    delay(2000);

    return;
  }

  // AES-GCM encryption
  result = mbedtls_gcm_crypt_and_tag(
    &gcm,
    MBEDTLS_GCM_ENCRYPT,
    plaintextLen,
    nonce,
    IV_SIZE,
    NULL,
    0,
    (const unsigned char*)plaintext.c_str(),
    ciphertext,
    TAG_SIZE,
    tag
  );

  if (result != 0) {

    Serial.println("ERROR: AES-GCM encryption failed");

    mbedtls_gcm_free(&gcm);

    delay(2000);

    return;
  }

  mbedtls_gcm_free(&gcm);

  // Convert binary data to hexadecimal
  String nonceHex =
    bytesToHex(nonce, IV_SIZE);

  String ciphertextHex =
    bytesToHex(ciphertext, plaintextLen);

  String tagHex =
    bytesToHex(tag, TAG_SIZE);

  // Packet:
  // NONCE|CIPHERTEXT|AUTH_TAG
  String packet =
    nonceHex +
    "|" +
    ciphertextHex +
    "|" +
    tagHex;

  Serial.println("AES-256-GCM encryption SUCCESS!");

  Serial.print("Nonce: ");
  Serial.println(nonceHex);

  Serial.print("Ciphertext: ");
  Serial.println(ciphertextHex);

  Serial.print("Auth Tag: ");
  Serial.println(tagHex);

  Serial.print("Encrypted packet length: ");
  Serial.println(packet.length());

  // Send encrypted packet to ESP32-B
  client.println(packet);

  Serial.println("Encrypted packet sent to ESP32-B.");

  // Wait for gateway response
  unsigned long start = millis();

  while (!client.available() &&
         millis() - start < 3000) {

    delay(10);
  }

  if (client.available()) {

    String response =
      client.readStringUntil('\n');

    response.trim();

    Serial.print("Gateway response: ");
    Serial.println(response);

  } else {

    Serial.println("No gateway response.");
  }

  delay(2000);
}