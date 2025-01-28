#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
//library for setting up the server
#include <arpa/inet.h>

//various libraries for encryption
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/opensslv.h>
#include <openssl/hmac.h>


#define PORT 8191           // Port of the server

#define N 10                //number of keys in the vault
#define MBITS 128           //size of each key in bits
#define M MBITS/8           //size of each key in bytes
#define P 4                 //dimension of the challenge

#define M1_SIZE 8           //M1 is made of 2 numbers of 32 bits (4 bytes)
#define M2_SIZE P + 4       //M2 is made of p numbers of 8 bits and a 32 bit (4 byte) int
#define PM3_SIZE 4 + 4 + P + 16//plaintext M3 is made of 2 random ints (r1, r2) each of 4 bytes, a M bytes random t1 and P numbers of 8 bits for C2
#define PM4_SIZE 4 + 16     //plaintext M4 is made of r2 (4 bytes) and t2 (16 bytes)    


char vault[N*M];            //secure vault

OPENSSL_init_crypto(OPENSSL_INIT_LOAD_LEGACY);      //allow legacy API from OpenSSL


//function declarations
//they are implemented at the end of the file
int query_from_db(char* vault_ptr, uint32_t dev);
int push_to_db(char* vault_ptr, uint32_t dev);
char checkID(uint32_t deviceID);
void create_challenge(uint8_t* array);

int main() {
    //stuff for setting up the server
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);


    uint8_t M1[M1_SIZE];
    uint8_t M2[M2_SIZE];
    uint8_t M3[1000];
    uint8_t PM3[PM3_SIZE+4];
    uint8_t M4[1000];
    uint8_t PM4[PM4_SIZE+12];
    for(int i = 20; i < 32; i++) PM4[i] = 0xee;     //padding to reach multiple of 16bytes to encrypt

    

    //setting up the server 
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Errore nella creazione del socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Binding error");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 1) < 0) {
        perror("Listen error");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    // accept connection from the device
    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
    if (client_fd < 0) {
        perror("Accept error");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("connected to client %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));


    //The stuff needed to setup the server is all done
    //now start with the implementation of the authentication method

    // Receive M1
    int bytes_received = recv(client_fd, M1, M1_SIZE, 0);
    if (bytes_received < 0) {
        perror("Error during reception");
        close(client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("RECEIVED M1 [%d] = ", M1_SIZE);
    for (int i = 0; i < bytes_received; i++) {
        printf("%02x ", M1[i]);
    }
    printf("\n");

    //read data and check if deviceID is valid
    uint32_t* buf = (uint32_t*) M1;
    uint32_t deviceID = buf[0];
    uint32_t sessionID = buf[1];
    printf("deviceID = %x, sessionID = %x\n", buf[0], buf[1]);

    if(!checkID(deviceID)) {
        perror("DeviceID is not valid");
        close(client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    else{
        //if the deviceID is valid
        //read the vault from the database
        if(!query_from_db(vault, deviceID)) {
            printf("Database was not reachable (= the file vault.hex was not found)\nAbort\n");
            return 0;
        }

        printf("\ndeviceID is valid! Quering the associated vault from database:\n");
        for(uint8_t i = 0; i < N; i++){
        printf("key %x = ", i);
        for(uint8_t j = 0; j < M; j++){
            printf("%02x ", (uint8_t)vault[i*M +j]);
        }
        printf("\n");
        }
    }








    //we need to craft the message M2 = {C1, r1}
    //it will be made of the concatenation of C1 and r1
    printf("\n\n\n-----Now create M2 and respond-----\n");

    //generate the challenge C1, made of P distinct random numbers between 0 and N-1
    uint8_t* C1 = M2;
    create_challenge(C1);
    printf("C1 was created = { ");
    for(int i = 0; i < P; i++) printf("%02x ", C1[i]);
    printf("}\n");
    
    //generate the random number
    uint32_t* r1 = (uint32_t*) (M2+P);
    *r1 = arc4random();
    printf("r1 was generated = %x\n", r1[0]);

    printf("M2 was sent [%d bytes] = ", M2_SIZE);
    for(int i = 0; i < M2_SIZE; i++) printf("%02x ", M2[i]);
    printf("\n");
    int bytes_sent = send(client_fd, M2, M2_SIZE, 0);
    if (bytes_sent < 0) {
        perror("Error during response");
        close(client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }







    
     printf("\n\n\n-----Now prepare to receive M3 and process it-----\n");
    // RECEIVE M3
    int M3_SIZE = 0;
    //receive one byte at a time; if it reads \r\n M3 is ended
    //I kinda borrowed this from HTTP
    while(1){
        if(read(client_fd, M3+M3_SIZE, 1)){
            M3_SIZE++;
            if(M3_SIZE > 1 && M3[M3_SIZE-1] == '\n' && M3[M3_SIZE-2] == '\r') break;
        }
    }
    M3_SIZE -= 2;

    printf("M3 (encrypted) was received [%d bytes] = ", M3_SIZE);
    for (int i = 0; i < M3_SIZE; i++) {
        printf("%02x ", (uint8_t) M3[i]);
    }
    printf("\n");

    //now decipher M3
    //compute k1
    uint8_t k1[M];
    for(char j = 0; j < M; j++) k1[j] = (uint8_t) vault[C1[0]*M + j];
    for(char i = 1; i < P; i++){                            //for each key selected by the challenge
      for(char j = 0; j < M; j++) k1[j] ^= (uint8_t) vault[C1[i]*M + j]; //compute the XOR, for each byte
    }

    printf("k1 was computed = ");
    for(int i = 0; i < M; i++){
        printf("%02x ", (uint8_t) k1[i]);
    }
    printf("\n");

    //create the iv known by both parties
    uint32_t iv[4] = {*r1, *r1, *r1, *r1};

    AES_KEY dec_key;    
    AES_set_decrypt_key(k1, MBITS, &dec_key); // Size of key is in bits
    AES_cbc_encrypt(M3, PM3, M3_SIZE, &dec_key, (uint8_t*) iv, AES_DECRYPT);

    printf("M3 was decrypted [%d bytes] = ", PM3_SIZE);
    for(int i = 0; i < PM3_SIZE; i++){
        printf("%02x ", (uint8_t) PM3[i]);
    }
    printf("\n");

    printf("\nNow process the decrypted message\n");
    //check if received r1 is correct
    uint32_t* rec_r1 = (uint32_t*) PM3;
    printf("Authenticate client: sent r1 = %02x, received r1 = %02x\n", *r1, *rec_r1);
    if(*rec_r1 != *r1) {
        printf("Client not authenticated. ABORT!!!\n");
        return 1;
    }
    else printf("The two values of r1 match. Client authenticated correctly\n\n");

    uint8_t* t1 = (PM3+4);
    printf("t1 = ");
    for(int i = 0; i < M; i++) printf("%02x ", t1[i]);
    printf("\n");

    uint8_t* C2 = PM3+20;
    printf("C2 = { ");
    for(int i = 0; i < P; i++) printf("%02x ", C2[i]);
    printf("}\n");

    uint32_t* r2 = (uint32_t*) (C2+P);
    printf("r2 = %x\n", *r2);







    printf("\n\n\n-----Now create M4, cipher it and respond-----\n");

    ((uint32_t*)PM4)[0] = *r2;  //add r2 to plaintext M4
    uint8_t* t2 = PM4+4;
    for(int i = 0; i < M; i++) t2[i] = arc4random(); //create t2 and add it to plaintext M4

    printf("t2 was generated = ");
    for(int i = 0; i < M; i++) printf("%02x ", t2[i]);
    printf("\n");

    printf("PLAINTEXT M4 [%d bytes] = ", PM4_SIZE);
    for(int i = 0; i < PM4_SIZE; i++) printf("%02x ", PM4[i]);
    printf("\n");
    

    //compute k2
    char k2[M];
    for(char j = 0; j < M; j++) k2[j] = vault[C2[0]*M + j];
    for(char i = 1; i < P; i++){                            //for each key selected by the challenge
      for(char j = 0; j < M; j++) k2[j] ^= vault[C2[i]*M + j]; //compute the XOR, for each byte
    }
    //XOR it with t1
    for(char j = 0; j < M; j++) k2[j] ^= t1[j];

    printf("k2 was computed = ");
    for(int i = 0; i < M; i++){
        printf("%02x ", (uint8_t) k2[i]);
    }
    printf("\n");


    //cipher M4
    printf("\nUse k2 to encrypt plaintext M4\n");
    uint32_t iv2[4] = {*r2, *r2, *r2, *r2};
    uint8_t* riv = (uint8_t*) iv2;

    AES_KEY enc_key;    
    AES_set_encrypt_key((uint8_t*) k2, MBITS, &enc_key); // Size of key is in bits
    AES_cbc_encrypt(PM4, M4, PM4_SIZE+12, &enc_key, riv, AES_ENCRYPT);

    int M4_SIZE = 0;
    uint32_t* p = (uint32_t*) M4;


    //compute size of ciphered message M4
    while(1){
        if(*p) M4_SIZE += 4;
        else break;
        p++;
        printf("%x", *p);
    }
    printf("\n");
    int excess = M4_SIZE%16;
    M4_SIZE -= excess;

    //add the terminator before sending
    M4[M4_SIZE] = '\r';
    M4[M4_SIZE+1] = '\n';

    //send M4
    bytes_sent = send(client_fd, M4, M4_SIZE+2, 0);
    if (bytes_sent < 0) {
        perror("Error during response");
        close(client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("M4 CIPHERTEXT was sent [%d bytes] = ", M4_SIZE);
    for(int i = 0; i < M4_SIZE; i++) printf("%x ", M4[i]);






    printf("\n\n\n-----Authentication complete-----\n");
    //compute the final SESSION KEY t
    uint8_t t[M];
    for(int i = 0; i < M; i++) t[i] = t1[i] ^ t2[i];


    printf("The SESSION KEY T was computed = ");
    for(int i = 0; i < M; i++) printf("%02x ", t[i]);
    printf("\n\n\n");


    //NOW THE DEVICE AND THE SERVER HAVE A SHARED SECRET KEY T AND CAN START SENDING MESSAGGES
    //communication is beyond the scope of the paper, but here is just an example
    uint8_t message[64];        //buffer for the plaintext message
    uint8_t encr_msg[100];      //buffer for the received ciphered message
    uint8_t ivm[M];             //buffer for the received IV
    uint8_t ivm_copy[M];        //copy of the IV because the encryption method modifies it
    uint8_t msg_len = 0;        //length of received message

    //read IV
    read(client_fd, ivm, M);
    for(int i = 0; i < M ; i++) ivm_copy[i] = ivm[i];

    //read message
    while(1){
        if(read(client_fd, (encr_msg+msg_len), 1)){
            msg_len++;
            if(msg_len > 1 && encr_msg[msg_len-1] == '\n' && encr_msg[msg_len-2] == '\r') break;
        }
    }
    msg_len -= 2;

    //decrypt the received message
    AES_KEY t_key;    
    AES_set_decrypt_key(t, MBITS, &t_key);
    AES_cbc_encrypt(encr_msg, message, 64, &t_key, ivm, AES_DECRYPT);

    printf("Received a message from device\nIV = ");
    for(int i = 0; i < M; i++) printf("%x ", ivm_copy[i]);
    printf("\nCiphertext [64 bytes] = ");
    for(int i = 0; i < 64; i++) printf("%x ", encr_msg[i]);
    printf("\n\nDecryption using SESSION KEY T\n");
    printf("Plaintext [64 bytes] = ");
    for(int i = 0; i < 64; i++) printf("%c", message[i]);
    printf("\n");


    


    // Chiusura delle connessioni
    close(client_fd);
    close(server_fd);

    printf("\nSESSION CLOSED.\n");

    //now it is time to update the vault
    printf("\n-----Update the vault-----\n");

    //MD5 will be used to compute the HMAC, because it returns a 128 bit result
    //the key is the message sent
    //the data to hash is the vault
    printf("HMAC of the vault (with MD5) = ");
    uint8_t h[16];
    uint32_t hlen;

    HMAC(EVP_md5(), message, 64, (uint8_t*) vault, M*N, h, &hlen);
    
    for(int i = 0; i < 16; i++) printf("%02x ", h[i]);
    printf("\n");

    //buffer for the new vault
    uint8_t new_vault[N*M];
    printf("New vault: \n");

    for(uint8_t i = 0; i < N; i++){
      printf("key %x = ", i);
      for(uint8_t j = 0; j < M-1; j++){
        new_vault[i*M +j] = h[j] ^ vault[i*M + j];
        printf("%02x ", new_vault[i*M +j]);
      }
      new_vault[i*M + M-1] = h[M-1] ^ vault[i*M + M-1];
      new_vault[i*M + M-1] ^= i;
      printf("%02x\n", new_vault[i*M +M-1]);
    }
    
    //push the new vault to the secure database
    push_to_db(new_vault, deviceID);
    printf("\nThe new vault was pushed to the database!\n");


    return 0;
}


char checkID(uint32_t deviceID){
    //implement some kind of device identification
    //it is not in the scope of the authorization methods of the paper
    return 1;
}


void create_challenge(uint8_t* array){
    //use Knuth algorithm to find P distinct random number in a set of N random numbers
    int in, ip;

    ip = 0;

    for (in = 0; in < N && ip < P; ++in) {
    int rn = N - in;    //remaining indexes to choose from
    int rp = P - ip;    //indexes we still need to pick
    if (arc4random_uniform(rn) < rp)
        array[ip++] = in; //pick index
    }
    //the array contains the numbers in increasing order, but that doesn't matter
    //because the order does not affect the result of the XOR they will be used for
}


//this is a dummy function that simulates querying the db from a secure vault
//it just reads from file because the db is not the important part of the implementation
int query_from_db(char* vault_ptr, uint32_t dev){
    FILE* in;
    if((in = fopen("vault.hex", "rt")) != NULL){
        for(int i = 0; i < N*M; i++) fscanf(in, "%c", vault_ptr+i);
        fclose(in);
        return 1;
    }
    else return 0;
}

//same as the other function
int push_to_db(char* vault_ptr, uint32_t dev){
    FILE* in;
    if((in = fopen("vault.hex", "w")) != NULL){
        for(int i = 0; i < N*M; i++) fprintf(in, "%c", vault_ptr[i]);
        fclose(in);
        return 1;
    }
    else return 0;
}