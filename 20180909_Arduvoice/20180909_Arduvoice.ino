#include <Servo.h>

Servo servo1;
Servo servo2;
Servo servo3;
Servo servo4;
Servo servo5;

void setup() {
  // put your setup code here, to run once:
  servo1.attach(3);
  servo2.attach(5);
  servo3.attach(6);
  servo4.attach(9);
  servo5.attach(10);
}

void loop() {
  // put your main code here, to run repeatedly:
for(int i=0;i<180;i++){
  servo1.write(i);
  servo2.write(i);
  servo3.write(i);
  servo4.write(i);
  servo5.write(i);
  delay(10);
  }
  for(int i=180;i>0;i--){
    servo1.write(i);
    servo2.write(i);
    servo3.write(i);
    servo4.write(i);
    servo5.write(i);
   delay(10);
    }
}
