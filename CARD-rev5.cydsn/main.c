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

int main (void)
{
    CyGlobalIntEnable;      /* Enable global interrupts */
    
    UART_Start();
    
    uint8_t digest[32];
    cf_sha256_context hash_ctx;
    cf_sha256_init(&hash_ctx);
    
    for(size_t i = 0; i < 12; i++)
        cf_sha256_update(&hash_ctx, "Hello World!", 12);
    cf_sha256_digest_final(&hash_ctx, digest);
    printUART((char *)digest, 32);
    
    printUART("Hey, PSoC1\t", 11);
    
    
    
    uint8_t out[16];
    uint8_t out2[16];
    const void *iv =  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    const void *key = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
    const void *inp = "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a";
    const void *expect = "\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d";

    cf_aes_context aes;
    cf_aes_init(&aes, key, 16);

    cf_cbc cbc;
    cf_cbc_init(&cbc, &cf_aes, &aes, iv);
    cf_cbc_encrypt(&cbc, inp, out, 1);
    printUART(out, 16);
    printUART((char *)out, 16);
    UART_PutArray(out, 16);
    printUART("HeyPSoC2\t", 11);
    
    cf_cbc_init(&cbc, &cf_aes, &aes, iv);
    cf_cbc_decrypt(&cbc, out, out2, 1);
    
    printUART(out2, 16);
    printUART("HeyPSoC3\t", 11);
    
    uint8 message[128];
    /* Declare variables here */

    /*cf_aes_context aes_ctx;
    cf_cbc cbc_ctx;
    uint8_t outbuf[16];
    
    //const uint8_t *key1 = {0xe6, 'R', '|', 0x84,'x', 0xce, 0x96, 0xa5, 'T',0xac,0xd8,'l',0xd0,0xe4,'L','f',0xf6,'&',0x16,'E',0xfa,'/',0x9b,0xa2,0xea,'!',0xce,'Y',0x85,0xbe,'\\','r','a'};
    const void *key1 = "\xe6" "R" "\x84" "x" "\xce" "\x96" "\xa5" "T" "\xac\xd8" "l" "\xd0\xe4" "Lf" "\xf6" "&" "\x16" "E" "\xfa" "/" "\x9b\xa2\xea" "!" "\xce" "Y" "\x85\xbe" "\\r";
    const void *iv = "this is an iv";
    const void *inbuf = "facefeed";
    uint8_t cbuf[] = {0x0e, 'p', 0xbd, 'l',0xa0, 'D','6',0x0b,0x00,'\\','W',0x87,0xca,'\\'};
    
    cf_aes_init(&aes_ctx, key1, 32);
    cf_cbc_init(&cbc_ctx, &cf_aes, &aes_ctx, iv);
    
    cf_cbc_encrypt(&cbc_ctx, inbuf, outbuf, 1);
    
    printUART("Hey, PSoC2\t", 11);
    
    UART_PutArray(outbuf, 16);
    
    
    cf_cbc_decrypt(&cbc_ctx, cbuf, outbuf, 1);
    
    printUART(outbuf, 16); */
    
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
