#include <SoftwareSerial.h>
#include <Servo.h>
//모터 핀번호 선언. 방향을 제어할때 사용
int motor1 = 12;
int motor2 = 13;
//속도를 제어하는 핀번호 선언.
int speed1 = 3;
int speed2 = 11;
int TX = 6;
int RX = 7;
SoftwareSerial BTSerial(TX, RX);
Servo myservo;

void setup() {
  Serial.begin(9600); //시리얼 통신 설정  //모든 핀모드를 OUTPUT으로 설정
  BTSerial.begin(9600); //시리얼 통신 설정  //모든 핀모드를 OUTPUT으로 설정
  pinMode(motor1, OUTPUT);
  pinMode(motor2, OUTPUT);

  pinMode(speed1, OUTPUT);
  pinMode(speed2, OUTPUT);
  //서보모터의 핀번호 설정. 초기각도를 0도로 설정
  myservo.attach(4);
  myservo.write(0);
}

void loop() {
  if (BTSerial.available()) {
    switch (BTSerial.read())
    {
      case 'A':
        Serial.println("7");
        setMotors(0, 255, 0, 1000);
        break;

      case 'B':
        Serial.println("8");
        setMotors(1023, 255, 1500, 1000);
        break;

      case 'C':
        Serial.println("9");
        setMotors(0, 0, 0, 0);
        break;

      case 'D':
        Serial.println("10");
        setMotors(1023, 0, 1500, 0);
        break;

      case 'R':
        Serial.println("0");
        returnSet();
        break;

    }
  }
}
void setMotors(int velo1, int velo2, int delay1, int delay2) {
  //motor1 제어
  digitalWrite(motor1, LOW);
  analogWrite(speed1, velo1);
  delay(delay1);
  analogWrite(speed1, 0);
  delay(0);

  //motor2 제어
  digitalWrite(motor2, LOW);
  analogWrite(speed2, velo2);
  delay(delay2);
  analogWrite(speed2, 0);
  delay(100);
  turn();
  returnSet();
}

void returnSet()  //다시 제자리로 돌아가는 함수
{
  digitalWrite(motor1, HIGH);
  analogWrite(speed1, 1023);
  delay(1000);
  digitalWrite(motor2, HIGH);
  analogWrite(speed2, 1023);
  delay(1000);
  analogWrite(speed1, 0);
  analogWrite(speed2, 0);
}

void turn() //서보모터를 움직여 서랍을 밀어내는 함수
{
  myservo.write(100); //서보모터의 각도를 100도로 지정
  delay(1000);
  myservo.write(0);
  delay(500); //1초뒤 다시 0도로 지정
}
