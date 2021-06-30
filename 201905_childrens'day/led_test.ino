int led1 = 13;
int led2 = 12;
int led3 = 11;
int led4 = 10;
int led5 = 9;
int led6 = 8;

void setup() {
  // put your setup code here, to run once:
  for (int i = 8; i < 14; i++) {
    pinMode(i, OUTPUT);
  }

}

void loop() {
  // put your main code here, to run repeatedly:
  digitalWrite(8,HIGH);
  
}
