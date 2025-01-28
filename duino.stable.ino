#include <WiFi.h>
#include <Preferences.h>
#include "AESLib.h"
#include <MD5Builder.h>

//setup connection to WiFi
const char* ssid = "PUT HERE YOUR SSID";
const char* password = "PUT HERE YOUR PASSWORD";
//server data
const char* server_ip = "PUT HERE THE IP ADDRESS OF THE SERVER";
const uint16_t server_port = 8191;    

WiFiClient client;


#define N 10                //number of keys in the vault
#define MBITS 128           //size of each key in bits
#define M MBITS/8           //size of each key in bytes
#define P 4                 //dimension of the challenge

#define M1_SIZE 8             //M1 is made of 2 numbers of 32 bits (4 bytes)
#define M2_SIZE P + 4       //M2 is made of P numbers of 8 bits and a 32 bit (4 byte) int
#define PM3_SIZE 4 + 16 + P + 4//plaintext M3 is made of 2 random ints (r1, r2) each of 4 bytes, random t1 of 16 bytes, and P numbers of 8 bits for C2
#define PM4_SIZE 4 + 16     //plaintext M4 is just a random 32 bit and a random 128 bit (tot = 20 bytes)

//create sessionID and DeviceID
uint32_t SessionID = 0x12345678;
uint32_t DeviceID = 0x34345656;

//this is the key to decipher the vault stored in memory
uint8_t memory_key[16] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB};
//and this is the IV
uint8_t memory_iv[16] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
//save a copy because the encryption method changes the IV, and we need to use it 2 times
uint8_t memory_iv_copy[16] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};

//declaration of the function to create the challenge
//it is defined at the end of the file
int create_challenge(uint8_t* array);


//run this code once
void setup() {

  char vault[N*M];              //buffer for the deciphered vault
  uint8_t crypto_vault[N*M];    //buffer for the ciphered version of the vault
  uint8_t M1[M1_SIZE];
  uint8_t M2[M2_SIZE];
  char PM3[PM3_SIZE+4];  //plaintext M3; need to pad to a multiple of key size 
  memset(PM3+PM3_SIZE, 0xdd, 4*sizeof(char));
  char M3[1000];
  char PM4[PM4_SIZE+12];  //plaintext M4; need to leave space to reach a multiple of key size
  uint8_t M4[1000];

  Serial.begin(115200);

  // Connect to WiFi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConnected to WiFi");

  //Retrieve the vault from the persistent memory of the ESP32
  Serial.println("Retrieving the vault from the memory:");
  Preferences memory;   //object that allows us to access the EEPROM of the ESP32
  AESLib aes;           //object used for CBC encryption and decryption

  memory.begin("vault", false);   //initializes the object in the namespace "vault"
  if(!memory.getBytes("vault_bytes", crypto_vault, M*N)){
    //if the memory did not contain the vault, set it to default value
    Serial.println("(memory did not contain the vault... Setting to default value)");
    String v = "kldemc30vcsa01lbsdf93jv9j93jkdnmslkjdfklnn28fjs5loremipsumlosdfvdjsf93jf393jfj39230fif3ifi303kvvgspoo3o3ds2szzzzdjf93j2jfbbhbh55kjvjkvdjvjvjvjvjsiummmmmmmmmmmmm";
    for(int i = 0; i < N*M; i++) vault[i] = v[i];
  }
  else{
    //if the vault was in memory, decipher it
    aes.decrypt(crypto_vault, N*M, (uint8_t*) vault, memory_key, MBITS, memory_iv);
  }
  
  //print the vault
  for(uint8_t i = 0; i < N; i++){
      Serial.printf("key %x = ", i);
      for(uint8_t j = 0; j < M; j++){
        Serial.printf("%02x ", (uint8_t) vault[i*M +j]);
      }
      Serial.printf("\n");
    }

  // Connect to the server
  if (client.connect(server_ip, server_port)) {
    Serial.println("Connected to the server");

    //start the communication with message M1, in plaintext
    //M1 = DeviceID||SessionID
    Serial.printf("\n\n\n-----Now create M1 and send it-----\n");
    uint32_t* buf = (uint32_t*) M1;
    buf[0] = DeviceID;
    buf[1] = SessionID;
    Serial.printf("DeviceID = %08x, SessionID = %08x\n", buf[0], buf[1]);
    
    client.write(M1, M1_SIZE);

    Serial.printf("M1 was sent = ");
    for(int i = 0; i < M1_SIZE; i++) Serial.printf("%02x ", M1[i]);
    Serial.printf("\n");











    Serial.printf("\n\n\n-----Now receive M2 and process it-----\n");
    //read response from the server
    while (client.connected()) {
      if (client.available()) {
        //M2 = {C1, r1}
        //C1 = challenge, is a set of p values (p < n) each corresponding to the index of a key from the vault
        //r1 = random number   
        client.read(M2, M2_SIZE);
        Serial.printf("M2 was received [%d bytes] = ", M2_SIZE);
        for(int i = 0; i < M2_SIZE - 1; i++) Serial.printf("%02x ", M2[i]);
        Serial.printf("%02x\n", M2[M2_SIZE-1]);
        
        break;
      }
    }

    //process M2 (it was plaintext)
    uint8_t* C1 = M2;
    uint32_t r1 = *((uint32_t*)(M2+P));
    Serial.printf("r1 = %02x\n", r1);
    Serial.printf("C1 = { ");
    for(char i = 0; i < P; i++){
      Serial.printf("%02x ", C1[i]);
    }
    Serial.printf("}\n");








    Serial.printf("\n\n\n-----Now create M3, cipher it and respond-----\n");
        //generate the response as r1||t1||{C2, r2}
    //and then encrypt it with the shared key k1
    ((uint32_t*)PM3)[0] = r1;
    uint8_t* t1 = (uint8_t*)(PM3+4);
    for(int i = 0; i < M; i++) t1[i] = random();  //generate 128bit random t1
    Serial.printf("t1 was generated = ");
    for(int i = 0; i < M; i++) Serial.printf("%02x ", t1[i]);
    Serial.println();

    char* C2 = PM3+20;
    create_challenge(C2);
    Serial.printf("C2 was created = { ");
    for(int i = 0; i < P; i++) Serial.printf("%02x ", C2[i]);
    Serial.println("}");
    
    uint32_t* r2 = (uint32_t*)(C2+P);
    *r2 = random();
    Serial.printf("r2 was generated = %02x\n", *r2);

    Serial.printf("PLAINTEXT M3 [%d bytes] = ", PM3_SIZE);
    for(int i = 0; i < PM3_SIZE; i++){
        Serial.printf("%02x ", (uint8_t) PM3[i]);
    }

    Serial.printf("\nNow compute the key k1 and cipher M3");
    //generate temporary key k1
    //k1 is the result of the XOR operation on all keys indexed in C1
    char k1[M];

    for(char j = 0; j < M; j++) k1[j] = vault[C1[0]*M + j];
    for(char i = 1; i < P; i++){                            //for each key selected by the challenge
      for(char j = 0; j < M; j++) k1[j] ^= vault[C1[i]*M + j]; //compute the XOR, for each byte
    }
    Serial.printf("k1 was computed = ", k1);
    for(int i = 0; i < M; i++) Serial.printf("%02x ", k1[i]);
    Serial.println();

    //cipher the message
    uint32_t iv[4] = {r1, r1, r1, r1};
    uint32_t M3_SIZE = aes.encrypt((uint8_t*)PM3, PM3_SIZE+4, (uint8_t*) M3, (uint8_t*) k1, MBITS, (uint8_t*) iv);

    Serial.printf("CIPHERTEXT M3 was sent [%d bytes] = ", M3_SIZE);
    for (int i = 0; i < M3_SIZE; i++) {
      Serial.printf("%02x ", (uint8_t)M3[i]);
    }
    Serial.println();

    M3[M3_SIZE] = '\r';
    M3[M3_SIZE+1] = '\n';
    client.write(M3, M3_SIZE+2);





    


    Serial.printf("\n\n\n-----Now receive M4 decipher it and process it-----\n");
     //read response from the server

    uint32_t M4_SIZE =  0;
    while (client.connected()) {
      if (client.available()) {
        //M4 = enc{k1^t1, r2||t2}
        //r2 = random number 32 bit
        //t2 = random number 128 bit
        while(1){
        if(client.read(M4+M4_SIZE, 1)){
            M4_SIZE++;
            if(M4_SIZE > 1 && M4[M4_SIZE-1] == '\n' && M4[M4_SIZE-2] == '\r') break;
          }
        
        }
        M4_SIZE -= 2; //ignore the \r\n
        Serial.printf("M4 (encrypted) was received [%d bytes] = ", M4_SIZE);
        for(int i = 0; i < M4_SIZE; i++) Serial.printf("%02x ", M4[i]);
        Serial.printf("\n");
        
        break;
      }
    }

    //compute k2 starting from C2
    Serial.printf("Compute k2 and decipher M4\n");
    char k2[M];
    for(char j = 0; j < M; j++) k2[j] = vault[C2[0]*M + j];
    for(char i = 1; i < P; i++){                            //for each key selected by the challenge
      for(char j = 0; j < M; j++) k2[j] ^= vault[C2[i]*M + j]; //compute the XOR, for each byte
    }
    //XOR it with t1
    for(char j = 0; j < M; j++) k2[j] ^= t1[j];

    Serial.printf("k2 was computed = ");
    for(int i = 0; i < M; i++){
        Serial.printf("%02x ", (uint8_t) k2[i]);
    }
    Serial.printf("\n");

    //decipher M4
    uint32_t iv2[4] = {*r2, *r2, *r2, *r2};
    int len = aes.decrypt((uint8_t*) M4, M4_SIZE, (uint8_t*) PM4, (uint8_t*) k2, MBITS, (uint8_t*) iv2);
    //Serial.printf("len = %d, expected M4_SIZE = %d\n", len, M4_SIZE);

    Serial.printf("M4 was decrypted [%d bytes] = ", PM4_SIZE);
    for(int i = 0; i < PM4_SIZE; i++) Serial.printf("%02x ", PM4[i]);
    Serial.printf("\n");

    Serial.printf("\nNow process the decrypted message\n");
    uint32_t* rec_r2 = (uint32_t*) PM4;
    uint8_t* t2 = (uint8_t*) PM4+4;

    Serial.printf("Authenticate server: sent r2 = %x, received r2 = %x\n", *r2, *rec_r2);
    if(*r2 != *rec_r2){
      Serial.printf("FAILED TO AUTHENTICATE THE SERVER. ABORT\n\n");
      //return 0;
    }
    else Serial.printf("The two values of r2 match. Server authenticated correctly\n\n");

    Serial.printf("t2 = ");
    for(int i = 0; i < M; i++) Serial.printf("%02x ", t2[i]);
    Serial.printf("\n");











    Serial.printf("\n\n\n-----Authentication complete-----\n");
    //compute the final SESSION KEY t
    uint8_t t[M];
    for(int i = 0; i < M; i++){
      t[i] = t1[i] ^ t2[i];
    }

    Serial.printf("The SESSION KEY T was computed = ");
    for(int i = 0; i < M; i++) Serial.printf("%02x ", t[i]);
    Serial.printf("\n\n\n");


    delay(1000);








    //NOW THE DEVICE AND THE SERVER HAVE A SHARED SECRET KEY T AND CAN START SENDING MESSAGGES
    //communication is beyond the scope of the paper, but here is just an example
    uint8_t ivm[M];
    uint8_t ivm_copy[M]; //need a copy because the encryption method modifies the iv
    for(int i = 0; i < M; i++){
      ivm[i] = random();
      ivm_copy[i] = ivm[i];
    }
    char message[] = "I am IoT device and can send messagges using key t, hi server :D";
    uint8_t encr_msg[1000];

    client.write(ivm_copy, M);  //send the IV before the message

    uint32_t encr_len = aes.encrypt((uint8_t*) message, 64, encr_msg, t, MBITS, ivm);

    encr_msg[encr_len] = '\r';    //add terminators
    encr_msg[encr_len+1] = '\n';
    
    client.write(encr_msg, encr_len+2);

    Serial.printf("Sent a message to the server\nPlaintext [64 bytes] = %s\nIV = ", message);
    for(int i = 0; i < M; i++) Serial.printf("%x ", ivm_copy[i]);
    Serial.printf("\nCiphertext [64 bytes] = ");
    for(int i = 0; i < 64; i++) Serial.printf("%x ", encr_msg[i]);
    Serial.println();


    // Close the connection when done
    client.stop();
    Serial.println("\n\nSESSION CLOSED.");







    //now it is time to update the vault
    Serial.println("\n-----Update the vault-----");

    //MD5 will be used to compute the HMAC, because it returns a 128 bit result
    //the key is the message sent
    //the data to hash is the vault
    Serial.printf("HMAC of the vault (with MD5) = ");
    uint8_t h[16];
    hmac_md5((uint8_t*) message, 64, (uint8_t*) vault, M*N, h);
    for(int i = 0; i < 16; i++) Serial.printf("%02x ", h[i]);
    Serial.println();

    uint8_t new_vault[N*M];     //buffer for the new vault (not so necessary but I used it for clarity)
    Serial.printf("New vault: \n");

    //each key gets XORed with h and its index in the vault
    for(uint8_t i = 0; i < N; i++){
      Serial.printf("key %x = ", i);
      for(uint8_t j = 0; j < M-1; j++){
        new_vault[i*M +j] = vault[i*M + j] ^ h[j];
        Serial.printf("%02x ", new_vault[i*M +j]);
      }
      //really need to xor with the index only the last byte because 
      //the index is never longer than 1 byte for n < 256
      new_vault[i*M +M-1] = vault[i*M + M-1] ^ h[M-1] ^ i;
      Serial.printf("%02x\n", new_vault[i*M +M-1]);
    }

    //before saving the vault in memory, cipher it
    len = aes.encrypt(new_vault, N*M, crypto_vault, memory_key, MBITS, memory_iv_copy);

    //finally, save the ciphered vault in the memory
    memory.putBytes("vault_bytes", crypto_vault, N*M);
    Serial.println("The new vault was saved in memory!");

    
  } else {
    Serial.println("Error during connection to the server.");
  }
}


//not needed here
void loop() {
  //doing usual IoT devices stuff here
}


void create_challenge(char* array){
    //use Knuth algorithm to find P distinct random number in a set of N random numbers
    int in, ip;

    ip = 0;

    for (in = 0; (in < N) && (ip < P); ++in) {
    int rn = N - in;    //remaining indexes to choose from
    int rp = P - ip;    //indexes we still need to pick

    long ran = random();

    if (ran%rn < rp)
        array[ip++] = in; //pick index
    }

    //the array contains the numbers in increasing order, but that doesn't matter
    //because the order does not affect the result of the XOR they will be used for
}


//this method is an adaptation to create a HMAC with MD5 using the standard espress-if library
//for the ESP32, made by Rosmianto A. Saputrom 
//https://github.com/rosmianto/hmac-md5/tree/master
void hmac_md5(uint8_t key[], int keyLength, uint8_t msg[], int msgLength, uint8_t result[]) {

	int blockSize = 64;
	byte baKey[64] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	byte hash_result[16];
	byte baOuterKeyPadded[blockSize];
	byte baInnerKeyPadded[blockSize];
	byte tempHash[16];
	MD5Builder md5;

	if(keyLength > blockSize) {
		md5.begin();
		md5.add(key, keyLength);
		md5.calculate();
		md5.getBytes(baKey);
	}
	else {
		for(int i = 0; i < keyLength; i++) {
			baKey[i] = key[i];
		}
	}

	for (int i = 0; i < blockSize; i++) {
		baOuterKeyPadded[i] = baKey[i] ^ 0x5C;
		baInnerKeyPadded[i] = baKey[i] ^ 0x36;
	}

	// return hash(o_key_pad ∥ hash(i_key_pad ∥ message)) // Where ∥ is concatenation
	md5.begin();
	md5.add(baInnerKeyPadded, blockSize);
	md5.add(msg, msgLength);
	md5.calculate();
	md5.getBytes(tempHash);

	md5.begin();
	md5.add(baOuterKeyPadded, blockSize);
	md5.add(tempHash, 16);
	md5.calculate();
	md5.getBytes(hash_result);

	memcpy(result, hash_result, 16);
}