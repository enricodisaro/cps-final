This repository contains the implementation for the authentication mechanism presented in the paper "Authentication of IoT Device and IoT Server Using Secure Vaults".

Reference report: https://www.overleaf.com/read/khwdffgksdpf#3a4618


-------------------------------------
To compile the file server.c

gcc server.c -o sw -lcrypto

It requires a UNIX platform to work, and it need OpenSSL installed

-------------------------------------
To compile the file device.ino
use the Arduino IDE

make sure to set the baudrate of the output terminal to 115200

-------------------------------------

If the connection is too slow, the communication might run into some issues.

Remember to change the ssid, the password and the server's IP in the arduino code.



Saving the ciphered vault in the EEPROM ensures data persistance, so even if the ESP32 turns off, it will have
the correct vault at power-on.

It is important that the vaults of the two devices is the same. The default vault for the ESP32 is the same  
originally present in vault.hex for the server. To change the vault of the server it is sufficient to modify
the vault.hex file, while for the ESP32 it's more complicated and you need to access the EEPROM from another 
arduino sketch with the Preferences.h library.



After months of using it, I still have no idea how does the Serial.print() work. I think that if too much data
is arriving, the Serial buffer becomes overwhelmed and just gives up, and stops printing anything.
To avoid this, there is a delay(1000) at one point in the code.


There are a lot o pointers in this program. There are a lot of casts, too. (sorry)
