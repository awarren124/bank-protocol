/* ========================================
 *
 * Copyright YOUR COMPANY, THE YEAR
 * All Rights Reserved
 * UNPUBLISHED, LICENSED SOFTWARE.
 *
 * CONFIDENTIAL AND PROPRIETARY INFORMATION
 * WHICH IS THE PROPERTY OF your company.
 *
 * ========================================
*/
#include <project.h>
#include "usbserialprotocol.h"
#include <stdlib.h>
#include <time.h>

#include "aes.h"
#include "modes.h"
#include "bitops.h"
#include "gf128.h"
#include "handy.h"
#include "sha2.h"

#define PIN_LEN 8
#define CARDID_LEN 36
#define PINCHG_SUC "SUCCESS"
#define PROV_MSG "P"
#define RECV_OK "K"
#define PIN_OK "OK"
#define PIN_BAD "BAD"
#define CHANGE_PIN '3'

#define PROVISIONED ((uint8*)(CY_FLASH_BASE + 0x6580))

#define PINHASH ((uint8*)(CY_FLASH_BASE + 0x6400))
#define CARDID ((uint8*)(CY_FLASH_BASE + 0x6480))
#define AES_KEY1 ((uint8*)(CY_FLASH_BASE + 0x3200))
#define MAGICWORD ((uint8*) (CY_FLASH_BASE + 0x3600))
#define CARDDATA ((uint8*)(CY_FLASH_BASE + 0x3280))

#define write_pin_hash(p) CySysFlashWriteRow(200, p);
#define write_cardid(u) CySysFlashWriteRow(201, u);
#define write_AES_key1(k) CySysFlashWriteRow(100, k);
#define write_magic_word(w) CySysFlashWriteRow(105, w);
#define write_carddata_hash(d) CySysFlashWriteRow(101, d);

#define BLOCK_SIZE 128

uint8 printUART(char * ptr, uint8 len){
    int i;
    for(i = 0; i<len; i++){
        UART_PutChar(ptr[i]);
    }
    return 0;
}

char *bin2hex(const unsigned char *bin, size_t len)
{
    char   *out;
    size_t  i;
 
    if (bin == NULL || len == 0)
        return NULL;
 
    out = malloc(len*2+1);
    for (i=0; i<len; i++) {
        
        out[i*2]   = "0123456789abcdef"[bin[i] >> 4];
        out[i*2+1] = "0123456789abcdef"[bin[i] & 0x0F];
    }
    out[len*2] = '\0';
 
    return out;
}

void printbin2hex(const unsigned char *bin, size_t len)
{
    size_t  i;
 
    if (bin == NULL || len == 0)
        return;
 
    for (i=0; i<len; i++) {
        
        UART_PutChar("0123456789abcdef"[bin[i] >> 4]);
        UART_PutChar("0123456789abcdef"[bin[i] & 0x0F]);
    }
    UART_PutString("\t\n");
}

void aes_32_encrypt(uint8_t *plaintext, uint8_t *output,  void* key, void* iv){
    cf_aes_context aes; 
    cf_aes_init(&aes, key, 32);
    
    cf_cbc cbc;
    cf_cbc_init(&cbc, &cf_aes, &aes, iv);
    
    cf_cbc_encrypt(&cbc, plaintext, output, 1);
    
    cf_aes_finish(&aes);
}

void aes_32_decrypt(uint8_t *input, uint8_t *output,  void* key, void* iv){
    cf_aes_context aes; 
    cf_aes_init(&aes, key, 32);
    
    cf_cbc cbc;
    cf_cbc_init(&cbc, &cf_aes, &aes, iv);
    
    cf_cbc_decrypt(&cbc, input, output, 1);
    
    cf_aes_finish(&aes);
}

void aes_encrypt_blocks(uint8_t * plaintext, uint8_t *output, void *key, void *iv, int blocks){
    if(blocks <= 0)
        return;
    aes_32_encrypt(plaintext, output, key, iv);
    aes_encrypt_blocks(&plaintext[16], &output[16], key, output, blocks-1);
}

void aes_decrypt_blocks(uint8_t * input, uint8_t *output, void *key, void *iv, int blocks){
    if(blocks <= 0)
        return;
    aes_32_decrypt(input, output, key, iv);
    aes_decrypt_blocks(&input[16], &output[16], key, input, blocks-1);
}

uint8_t pad_16(uint8_t *array, int p){
    if(p > 16 || p < 0){
        return 1;   
    }
    int i;
    for(i = 15; i > 15-p; i--){
	    array[i] = '_';
    }
    return 0;
}

/*
 * args:
 * array; input array
 * output; output array
 * size; capacity of array
*/
uint8_t pad_mult_16(uint8_t *array, uint8_t *output, int size)
{
    int i;
    int left = size % 16;
    int target = size+left;
    if(size % 16 == 0){
        return 0;
    }
    memcpy(output, array, size);
    for(i = target-1; i>=size; i--){
        output[i] = '_';   
    }
    return 0;
}

void sha256(char * input, uint8_t destination[32], uint8 size){
    cf_sha256_context hash_ctx;
    cf_sha256_init(&hash_ctx);
    cf_sha256_update(&hash_ctx, input, size);
    cf_sha256_digest_final(&hash_ctx, destination);
}

void gen_bytes(uint8_t * buffer, int size){
    int i;
    srand(time(NULL));
    for(i = 0; i<size; i++){
        buffer[i] = rand() % 256;   
    }
}

void slice(uint8_t * src, uint8_t * dest, size_t a, size_t b){
    size_t i = 0;
    for(size_t j = a; j < b; ++j){
        dest[i++] = src[j];
    }
}

// provisions card (should only ever be called once)
void provision()
{
    uint8_t message[128];
    uint8_t unHashedCardData[32];
    uint8_t cardDataHash[32];
    uint8_t hashedMagicWord[32];
    size_t magicWordSize;                  
    
    // synchronize with bank
    syncConnection(SYNC_PROV);
 
    pushMessage((uint8*)PROV_MSG, (uint8)strlen(PROV_MSG));
        
    // set hashed PIN
    pullMessage(message);
    uint8_t hashpin[32];
    sha256((char *)message, hashpin, 8);
    write_pin_hash(hashpin);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
    
    // set card ID
    pullMessage(message);
    write_cardid(message);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
    
    // set Key 1
    pullMessage(message);
    write_AES_key1(message);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
    
    // get expiration date and add it to carddata
    pullMessage(message);
    strncpy((char *)unHashedCardData, (char *)message, 4);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
    
    // get magic word 1, hash it, store it, then add it to carddata
    pullMessage(message);
    magicWordSize = strlen((char *)message);
    sha256((char *)message, hashedMagicWord, magicWordSize);
    write_magic_word(hashedMagicWord);
    strncat((char *)unHashedCardData, (char *)message, magicWordSize);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
    
    // hash carddata and store it
    sha256((char *)unHashedCardData, cardDataHash, 4 + magicWordSize);
    write_carddata_hash(cardDataHash);
    
}

void mark_provisioned()
{
    uint8 row[128];
    *row = 1;
    CySysFlashWriteRow(202, row);
}

int main (void)
{
    CyGlobalIntEnable;      /* Enable global interrupts */
    
    UART_Start();
    
    /* Declare variables here */
    
    uint8_t message[128];
    uint8_t iv[16];
    uint8_t cipherText[48];
    uint8_t concatReceived[41];
    uint8_t receivedPIN[PIN_LEN];
    uint8_t request[1];
    uint8_t key1prime[32];
    uint8_t hashedReceivedPIN[32];
    uint8_t cardDataToSend[100];
    uint8_t paddedCardDataToSend[112];
    uint8_t encryptedCardData[112];
    uint8_t ivToSend[16];
    uint8_t outgoingInfoBlock[128];
    
    
    // Provision card if on first boot
    if (*PROVISIONED == 0x00) {
        provision();
        mark_provisioned();
    }
    
    // Go into infinite loop
    while (1) {
        /* Place your application code here. */

        // synchronize communication with bank
        syncConnection(SYNC_NORM);
        
        // receive encrypted pin, request, and key 1'
        pullMessage(message);
        
        // parse iv
        slice(message, iv, 0, 16);
        
        // parse encrypted data
        slice(message, cipherText, 16, 64);
        
        aes_decrypt_blocks(cipherText, concatReceived, AES_KEY1, iv, 3);
        
        // parse encrypted parts
        slice(concatReceived, receivedPIN, 0, 8);
        slice(concatReceived, request, 8, 9);                           
        slice(concatReceived, key1prime, 9, 41);
        
        // hash received PIN and compare
        sha256((char *)receivedPIN, hashedReceivedPIN, 8);
        
        if(strncmp((char *)PINHASH, (char *)hashedReceivedPIN, 32)){
            pushMessage((uint8*)PIN_BAD, strlen(PIN_BAD));
        }else{
            // assembles card data
            strncpy((char *)cardDataToSend, (char *)CARDID, 36);
            strncat((char *)cardDataToSend, (char *)CARDDATA, 32);
            strncat((char *)cardDataToSend, (char *)MAGICWORD, 32);
            
            // pad to be encrypted
            pad_mult_16(cardDataToSend, paddedCardDataToSend, 100);
            
            // generates new encryption iv
            gen_bytes(ivToSend, 16);
            
            // encrypts card data
            aes_encrypt_blocks(paddedCardDataToSend, encryptedCardData, AES_KEY1, ivToSend, 7);
            
            // assembles final batch of information to send (iv and encrypted data)
            strncpy((char *) outgoingInfoBlock, (char *)iv, 16);
            strncat((char *) outgoingInfoBlock, (char *)encryptedCardData, 112);
            
            // sends the message
            pushMessage(outgoingInfoBlock, 128);
            
            // replace aes key 1
            write_AES_key1(key1prime);
        }
        
        
    }
}
