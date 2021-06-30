int led1 = 8;
int led2 = 9;
int led3 = 10;
int led4 = 11;
int led5 = 12;
int led6 = 13;

int sen1 = A0;
int sen2 = A1;
int sen3 = A2;

int a = 0;
int sensor1, sensor2, sensor3 = 0;

void setup() {
  for (int i = 8; i < 14; i++) {
    pinMode(i, OUTPUT);
  }

  pinMode(A0, INPUT);
  pinMode(A1, INPUT);
  pinMode(A2, INPUT);

  Serial.begin(9600);
}

void loop() {
  if (Serial.available())
    a = Serial.read();

  sensor1 = map(analogRead(sen1), 0, 1023, 0, 5000);
  sensor2 = map(analogRead(sen2), 0, 1023, 0, 5000);
  sensor3 = map(analogRead(sen3), 0, 1023, 0, 5000);
  Serial.println(sensor1);
  delay(200);
  Serial.println(sensor2);
  delay(200);
  Serial.println(sensor3);
  delay(200);

  if (a == 'A') {
    sensor2 = 0;
    sensor3 = 0;
    Serial.println("mode A");
    if (sensor1 > 2000) {
      for (int i = 8; i <= 13; i++) {
        digitalWrite(i, HIGH);
      }
    }
    else {
      for (int i = 8; i <= 13; i++)
        digitalWrite(i, LOW);
    }
  }


  else if (a == 'C') {
    sensor1 = 0;
    sensor3 = 0;
    Serial.println("mode C");
    if (sensor2 > 1900) {
      for (int i = 8; i <= 13; i++) {
        digitalWrite(i, HIGH);
      }
    }
    else {
      for (int i = 8; i <= 13; i++)
        digitalWrite(i, LOW);
    }
  }


  else if (a == 'B') {
    sensor1 = 0;
    sensor2 = 0;
    Serial.println("mode B");
    if (sensor3 > 1900) {
      for (int i = 8; i <= 13; i++) {
        digitalWrite(i, HIGH);
      }
    }
    else {
      for (int i = 8; i <= 13; i++)
        digitalWrite(i, LOW);
    }
  }
}
