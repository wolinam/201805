int led1 = 8;
int led2 = 7;
int led3 = 6;
int led4 = 5;
int led5 = 4;
int led6 = 3;

int sen1 = 9;
int sen2 = 10;
int sen3 = 11;

//int button1 = 12;
int button2 = 13;
int event = digitalRead(button2);
int sensor1 = digitalRead(sen1);
int sensor2 = digitalRead(sen2);
int sensor3 = digitalRead(sen3);


void setup() {
  for (int i = 3; i < 9; i++) {
    pinMode(i, OUTPUT);
  }
  for (int j = 9; j < 14; j++) {
    pinMode(j, INPUT);
  }
  Serial.begin(9600);
}

void loop() {
  //  digitalWrite(button1,LOW);
  //  digitalWrite(button2,LOW);
  //  int event = digitalRead(button2);

  if (event == HIGH) {
    Serial.println("event");
    for (int i = 3; i <= 8; i++) {
      digitalWrite(i, LOW);
      if (sensor1 == 1)
        digitalWrite(led1, HIGH);
        Serial.println(sensor1);
      if (sensor2 == 1)
        digitalWrite(led2, HIGH);
      if (sensor3 == 1)
        digitalWrite(led3, HIGH);
    }
    if(led1==HIGH&&led2==HIGH&&led3==HIGH)
      Serial.println("all");
  }

  if (event == LOW) {
    Serial.println("normal");
    sen1 = 0;
    sen2 = 0;
    sen3 = 0;
    for (int i = 3; i <= 8; i++) {
      digitalWrite(i, HIGH);
      Serial.println("light normal");
    }
  }
}
