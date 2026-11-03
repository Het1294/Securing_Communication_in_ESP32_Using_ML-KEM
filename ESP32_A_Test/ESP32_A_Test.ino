void setup() {
  Serial.begin(115200);

  delay(1000);

  Serial.println();
  Serial.println("================================");
  Serial.println(" Secure IoT ESP32 Test");
  Serial.println(" ESP32-A is working!");
  Serial.println("================================");
}

void loop() {
  Serial.println("ESP32-A running...");
  delay(2000);
}