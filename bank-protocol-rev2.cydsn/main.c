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
#include <stdio.h>

#include <mbedtls/aes.h>

int main (void)
{
    CyGlobalIntEnable;      /* Enable global interrupts */
    
    /* Place your initialization/startup code here (e.g. MyInst_Start()) */
    
    UART_Start();
    UART_PutString("hello world\n");
    
    //flash read/write
    
    /*
    char buffer[CY_FLASH_SIZEOF_ROW];
    for(uint i = 0; i<CY_FLASH_SIZEOF_ROW; i++)
        buffer[i] = 'A';
    
    int row = 1;
    CySysFlashWriteRow(row, &buffer);
    
    char buffer2[129];
    memcpy(buffer2, CY_FLASH_BASE + row*128, 128);
    buffer2[128] = 0;
    UART_UartPutString(buffer2);*/
    
    for(;;)
    {
       
        /* Place your application code here */
        
        //echo
        /*
        char c;
        
        c = UART_GetChar();
        
        if(c)
            UART_PutChar(c);
        */
        
        //constant encryption
        mbedtls_aes_context aes;

        unsigned char key[32];
        unsigned char iv[16];

        unsigned char input [128];
        unsigned char output[128];

        size_t input_len = 40;
        size_t output_len = 0;
        
        for(uint i = 0; i<input_len; i++){
            input[i] = 'a';
        }
        
        printf(input);
        
        mbedtls_aes_setkey_enc( &aes, key, 256 );
        mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 24, iv, input, output );
        
        printf(output);
        
        //UART_PutString("hello world\n");

    }
}
