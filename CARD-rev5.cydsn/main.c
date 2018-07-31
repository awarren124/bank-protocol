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

char *recvUART(uint8 size){
    char * ptr = malloc(sizeof(char) * size);
    int i;
    for( i = 0; i<size; i++){
        ptr[i] = getValidByte();
        //UART_PutChar(ptr[i]);
    }
    return ptr;
}

char *bin2hex(const unsigned char *bin, size_t len)
{
    char   *out;
    size_t  i;
 
    if (bin == NULL || len == 0)
        return NULL;
 
    out = malloc(len*2+1);
    //out = malloc(len*4);
    for (i=0; i<len; i++) {
        
        out[i*2]   = "0123456789ABCDEF"[bin[i] >> 4];
        out[i*2+1] = "0123456789ABCDEF"[bin[i] & 0x0F];
        /*
        out[i*4] = "\\";
        out[i*4+1] = "x";
        out[i*4+2]   = "0123456789ABCDEF"[bin[i] >> 4];
        out[i*4+3] = "0123456789ABCDEF"[bin[i] & 0x0F];
        */
    }
    out[len*2] = '\0';
 
    return out;
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

cf_cbc prep_aes_32(cf_aes_context aes, void* key, void* iv){
    cf_aes_init(&aes, key, 32);
    
    cf_cbc cbc;
    cf_cbc_init(&cbc, &cf_aes, &aes, iv);
    return cbc;
}

uint8_t pad_16(uint8_t *array, uint8 p){
    int i;
    for(i = p-1; i>=0; i--){
        array[i] = p;
    }
    return 0;
}

uint8_t sha256(uint8_t *input, uint8 size){
    uint8_t digest[32];
    cf_sha256_context hash_ctx;
    cf_sha256_init(&hash_ctx);
    for(uint8 i = 0; i < size; i++)
        cf_sha256_update(&hash_ctx, input, size);
    cf_sha256_digest_final(&hash_ctx, digest);
    return *digest;
}

int main (void)
{
    CyGlobalIntEnable;      /* Enable global interrupts */
    
    UART_Start();
    
    /* Declare variables here */
    
    printUART("started\n", 8);
    
    //void* key1 = recvUART(32);
    //free(key1);
    
    uint8_t digest[32];
    cf_sha256_context hash_ctx;
    
    cf_sha256_init(&hash_ctx);
    
    printUART("hashinit\n", 9);
    
    //for(size_t i = 0; i < 12; i++)
    cf_sha256_update(&hash_ctx, "Hello World!", 12);
    cf_sha256_digest_final(&hash_ctx, digest);
    
    printUART((char *)digest, 32);
    char *digesthex = bin2hex((unsigned char*)digesthex, 32);
    UART_PutString(digesthex);
    
    printUART("Hey, PSoC1\t", 11);
    
    
    
    uint8_t out[16];
    uint8_t out2[16];
    const void *iv =  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    const void *key = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
    const void *inp = "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a";
    const void *expect = "\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d";

    printUART("INPUT : ", 6);
    UART_PutString(inp);
    char *inphex = bin2hex((unsigned char *)inp, 16);
    UART_PutString(inphex);
    free(inphex);
    
    cf_aes_context aes;
    cf_aes_init(&aes, key, 16);

    cf_cbc cbc;
    cf_cbc_init(&cbc, &cf_aes, &aes, iv);
    cf_cbc_encrypt(&cbc, inp, out, 1);
    
    printUART("EXPECTED OUTPUT : ", 18);
    char * exphex = bin2hex((unsigned char*) expect, 16);
    free(exphex);
    
    UART_PutString(exphex);
    printUART("OUTPUT : ", 9);
    printUART((char *)out, 16);
    char * outhex = bin2hex((unsigned char*) out, 16);
    UART_PutString(outhex);
    free(outhex);
    
    //cf_cbc_init(&cbc, &cf_aes, &aes, iv);
    cf_cbc_decrypt(&cbc, out, out2, 1);
    
    char * out2hex = bin2hex(out2, 16);
    if(out2 == inp || out2hex == (char *)inp){
        printUART("successful decrypt\n", 19);   
    }
    else{
        printUART("unsuccessful decrypt\n", 21);   
    }
    
    printUART("HEX MESSAGE OUTPUT : ", 22);
    UART_PutString(out2hex);
    free(out2hex);
    
    printUART("HeyPSoC3\t", 11);
    
    cf_aes_finish(&aes);
    
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
                pushMessage(UUID, UUID_LEN);   
            }
        }
    }
}
