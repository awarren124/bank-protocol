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

#define PIN ((uint8*)(CY_FLASH_BASE + 0x6400))
#define UUID ((uint8*)(CY_FLASH_BASE + 0x6480))
#define PROVISIONED ((uint8*)(CY_FLASH_BASE + 0x6580))
#define write_pin(p) CySysFlashWriteRow(200, p);
#define write_uuid(u) CySysFlashWriteRow(201, u);

#define KEY1 ((uint8*)(CY_FLASH_BASE + 0x3200))
#define KEYA ((uint8*)(CY_FLASH_BASE + 0x3280))
#define KEYD ((uint8*)(CY_FLASH_BASE + 0x3360))
#define KEYF ((uint8*)(CY_FLASH_BASE + 0x3440))

#define CARDDATA ((uint8*)(CY_FLASH_BASE + 0x3520))

#define MAGICWORD ((uint8*) (CY_FLASH_BASE + 0x3600))

#define write_key1(k) CySysFlashWriteRow(100, k);
#define write_keya(k) CySysFlashWriteRow(101, k);
#define write_keyd(k) CySysFlashWriteRow(102, k);
#define write_keyf(k) CySysFlashWriteRow(103, k);

#define write_card_data(d) CySysFlashWriteRow(104, d);

#define write_magic_word(w) CySysFlashWriteRow(105, w);

#define BLOCK_SIZE 128

void mark_provisioned()
{
    uint8 row[128];
    *row = 1;
    CySysFlashWriteRow(202, row);
}

// provisions card (should only ever be called once)
void provision()
{
    uint8 message[128];
    
    // synchronize with bank
    syncConnection(SYNC_PROV);
 
    pushMessage((uint8*)PROV_MSG, (uint8)strlen(PROV_MSG));
        
    // set PIN
    pullMessage(message);
    write_pin(message);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
    
    // set account number
    pullMessage(message);
    write_uuid(message);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
}

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
        
        out[i*2]   = "0123456789ABCDEF"[bin[i] >> 4];
        out[i*2+1] = "0123456789ABCDEF"[bin[i] & 0x0F];
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
        
        UART_PutChar("0123456789ABCDEF"[bin[i] >> 4]);
        UART_PutChar("0123456789ABCDEF"[bin[i] & 0x0F]);
    }
    UART_PutString("\t\n");
}

int hexchr2bin(const char hex, char *out)
{
    if (out == NULL)
        return 0;
 
    if (hex >= '0' && hex <= '9') {
        *out = hex - '0';
    } else if (hex >= 'A' && hex <= 'F') {
        *out = hex - 'A' + 10;
    } else if (hex >= 'a' && hex <= 'f') {
        *out = hex - 'a' + 10;
    } else {
        return 0;
    }
 
    return 1;
}

size_t hexs2bin(const char *hex, unsigned char **out)
{
    size_t len;
    char   b1;
    char   b2;
    size_t i;
 
    if (hex == NULL || *hex == '\0' || out == NULL)
        return 0;
 
    len = strlen(hex);
    if (len % 2 != 0)
        return 0;
    len /= 2;
 
    *out = malloc(len);
    memset(*out, 'A', len);
    for (i=0; i<len; i++) {
        if (!hexchr2bin(hex[i*2], &b1) || !hexchr2bin(hex[i*2+1], &b2)) {
            return 0;
        }
        (*out)[i] = (b1 << 4) | b2;
    }
    return len;
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

void sha256(char * input, uint8 size, uint8_t destination[32]){
    cf_sha256_context hash_ctx;
    cf_sha256_init(&hash_ctx);
    cf_sha256_update(&hash_ctx, input, size);
    cf_sha256_digest_final(&hash_ctx, destination);
}

int main (void)
{
    CyGlobalIntEnable;      /* Enable global interrupts */
    
    UART_Start();
    
    /* Declare variables here */

    char * expiration = "0818";
    uint8_t shaexp[32];
    sha256(expiration, 32, shaexp);
    
    char * magicword = "hello";
    uint8_t shamag[32];
    sha256(magicword, 32, shamag);
    uint8_t * iv = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint8_t * key1 = "ABABABABABABABABABABABABABABABAB";
    
    /*
    uint8_t * m = "yo my name is bowen and i think im rly smart. have u ever thought about the universe. i have thats how smart i am.pppppppppppppp";
    uint8_t out[128];
    aes_encrypt_blocks(m, out, key1, iv, 8);
    uint8_t out2[128];
    aes_decrypt_blocks(out, out2, key1, iv, 8);
    printbin2hex(out, 128);
    printUART(out2, 128);
    */
    
    /*
    uint8_t * test = "hello xD how long is this?";
    int size = strlen((char*)test);
    uint8_t output[size + size%16];
    pad_mult_16(test, output, size);
    printUART(output, size + size%16);
    */
    
    uint8_t hashes[64];
    uint8_t card_data[64];
    
    memcpy(hashes, shaexp, 32);
    memcpy(&hashes, shamag, 32);
    aes_encrypt_blocks(hashes, card_data, key1, iv, 4);
    write_card_data(card_data);
    
    uint8 message[128];
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
        
        if (strncmp((char*)message, (char*)PIN, PIN_LEN)) {
            pushMessage((uint8*)PIN_BAD, strlen(PIN_BAD));
        } else {
            pushMessage((uint8*)PIN_OK, strlen(PIN_OK));
            
            // get command
            pullMessage(message);
            pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
            
            // change PIN or broadcast UUID
            if(message[0] == CHANGE_PIN)
            {
                pullMessage(message);
                write_pin(message);
                pushMessage((uint8*)PINCHG_SUC, strlen(PINCHG_SUC));
            } else {
                uint8_t uuid_temp[48];
                uint8_t encrypted_uuid[48];
                pad_mult_16(UUID, uuid_temp, UUID_LEN);
                aes_encrypt_blocks(uuid_temp, encrypted_uuid, key1, iv, 3);
                pushMessage(encrypted_uuid, 96);
                //pushMessage(UUID, UUID_LEN);
                
            }
        }
        
    }
}
