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
int distance1, distance2, distance3;


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

  distance1 = (27.61 / (sensor1 - 0.1696)) * 1000;
  Serial.print("distance1 = ");
  Serial.println(distance1);
  delay(500);
  distance2 = (27.61 / (sensor2 - 0.1696)) * 1000;
  Serial.print("distance2 = ");
  Serial.println(distance2);
  delay(500);
  distance3 = (27.61 / (sensor3 - 0.1696)) * 1000;
  Serial.print("distance3 = ");
  Serial.println(distance3);
  delay(500);

  if (distance1 < 25)
    digitalWrite(led1, HIGH);
  else
    digitalWrite(led1, LOW);
  if (distance2 < 25)
    digitalWrite(led2, HIGH);
  else
    digitalWrite(led2, LOW);
  if (distance3 < 25)
    digitalWrite(led3, HIGH);
  else
    digitalWrite(led3, LOW);

  char a = Serial.read();
  switch (a) {
    case 'b':
      sensor1 = 0;
      sensor2 = 0;
      sensor3 = 0;
      for (int i = 8; i <= 13; i++) {
        digitalWrite(i, HIGH);
        Serial.println("see");
      }
    case 'c':
      sensor1 = 0;
      sensor2 = 0;
      sensor3 = 0;
      for (int i = 8; i <= 13; i++) {
        digitalWrite(i, LOW);
        Serial.println("off");
      }
  }
}
