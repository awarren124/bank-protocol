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
#define UUID_LEN 36
#define PINCHG_SUC "SUCCESS"
#define PROV_MSG "P"
#define RECV_OK "K"
#define PIN_OK "OK"
#define PIN_BAD "BAD"
#define CHANGE_PIN '3'

#define AES_KEY1 ((uint8*)(CY_FLASH_BASE + 0x3200))

#define CARDDATA ((uint8*)(CY_FLASH_BASE + 0x3280))
#define MAGICWORD ((uint8*) (CY_FLASH_BASE + 0x3360))

#define PINHASH ((uint8*)(CY_FLASH_BASE + 0x6400))
#define CARDID ((uint8*)(CY_FLASH_BASE + 0x6480))
#define PROVISIONED ((uint8*)(CY_FLASH_BASE + 0x6580))

#define write_AES_key1(k) CySysFlashWriteRow(100, k);

#define write_card_hash(d) CySysFlashWriteRow(101, d);
#define write_magic_word_hash(w) CySysFlashWriteRow(102, w);

#define write_pin_hash(p) CySysFlashWriteRow(200, p);
#define write_cardid(u) CySysFlashWriteRow(201, u);

#define BLOCK_SIZE 128


uint8 printUART(char * ptr, uint8 len){
    int i;
    for(i = 0; i<len; i++){
        UART_PutChar(ptr[i]);
    }
    return 0;
}

void printbin2hex(const unsigned char *bin, size_t len)
{
    size_t  i;
 
    if (bin == NULL '' len == 0)
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
    if(p > 16 '' p < 0){
        return 1;   
    }
    int i;
    for(i = 15; i > 15-p; i--){
	    array[i] = '_';
    }
    return 0;
}

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

void mark_provisioned()
{
    uint8 row[128];
    *row = 1;
    CySysFlashWriteRow(202, row);
}

// provisions card (should only ever be called once)
void provision()
{
    uint8_t message[128];
    uint8_t unHashedCardData[32];
    uint8_t cardDataHash[32];
    uint8 magicWordSize = 10;                    ////////Temporary pls adjust
    
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
    
    // get magic word 1 and add it to carddata
    pullMessage(message);
    strncat((char *)unHashedCardData, (char *)message, magicWordSize);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
    
    // hash carddata and store it
    sha256((char *)unHashedCardData, cardDataHash, 4 + magicWordSize);
    write_card_hash(cardDataHash);
    
}

int main (void)
{
    CyGlobalIntEnable;      /* Enable global interrupts */
    
    // initialize UART
    UART_Start();

    char * expiration = "0818";
    uint8_t hashexp[32];
    sha256(expiration, hashexp, 32);
    
    char * magicword = "hello";
    uint8_t hashmag[32];
    sha256(magicword, hashmag, 32);
    
    uint8_t * iv = (unsigned char*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    write_AES_key1((unsigned char*)"ABABABABABABABABABABABABABABABAB");
    write_magic_word_hash(hashmag);
    
    uint8_t hashes[64];
    uint8_t card_data[64];
    
    memcpy(hashes, hashexp, 32);
    memcpy(&hashes, hashmag, 32);
    aes_encrypt_blocks(hashes, card_data, AES_KEY1, iv, 4);
    write_card_hash(card_data);
    
    uint8_t message[128];
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
        
        // receive pin number from ATM
        pullMessage(message);
        uint8_t hashpin[32];
        sha256((char *)message, hashpin, 8);
        if (strncmp((char*)message, (char*)PINHASH, 32)) {
            pushMessage((uint8*)PIN_BAD, strlen(PIN_BAD));
        } else {
            pushMessage((uint8*)PIN_OK, strlen(PIN_OK));
            
            // get request
            pullMessage(message);
            pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
            
            // change PIN or broadcast UUID
            if(message[0] == CHANGE_PIN)
            {
                pullMessage(message);
                sha256((char *) message, hashpin, 8);
                write_pin_hash(hashpin);
                pushMessage((uint8*)PINCHG_SUC, strlen(PINCHG_SUC));
            } else {
                uint8_t cardid_temp[48];
                uint8_t encrypted_uuid[48];
                pad_mult_16(CARDID, cardid_temp, UUID_LEN);
                aes_encrypt_blocks(cardid_temp, encrypted_uuid, AES_KEY1, iv, 3);
                pushMessage(encrypted_uuid, 96);
                //pushMessage(UUID, UUID_LEN);
                
            }
        }
        
    }
}
