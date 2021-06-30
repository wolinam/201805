int led1 = 8;
int led2 = 9;
int led3 = 10;
int led4 = 11;
int led5 = 12;
int led6 = 13;

int sen1 = A0;
int sen2 = A1;
int sen3 = A2;

int sensor1, sensor2, sensor3;


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

  sensor1 = map(analogRead(sen1), 0, 1023, 0, 5000);
  sensor2 = map(analogRead(sen2), 0, 1023, 0, 5000);
  sensor3 = map(analogRead(sen3), 0, 1023, 0, 5000);
  Serial.println(sensor1);

  if (sensor2 > 2000) {
    for (int i = 8; i <= 13; i++)
      digitalWrite(i, LOW);
    for (int i = 8; i <= 13; i++) {
      digitalWrite(i, HIGH);
      delay(200);
      digitalWrite(i, LOW);
      delay(200);
    }
  }


  else if (sensor1 > 2000) {
    for (int i = 8; i <= 13; i++)
      digitalWrite(i, LOW);
    for (int i = 8; i <= 13; i++) {
      digitalWrite(i, HIGH);
      Serial.println("A");
      delay(500);
    }
  }
  else if (sensor3 > 2000) {
    for (int i = 8; i <= 13; i++)
      digitalWrite(i, LOW);
    for (int i = 8; i <= 13; i++) {
      digitalWrite(i, HIGH);
      delay(500);
      digitalWrite(i, HIGH);
      delay(500);
    }
  }
}
