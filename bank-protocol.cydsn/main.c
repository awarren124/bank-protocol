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

int main (void)
{
    CyGlobalIntEnable;      /* Enable global interrupts */
    UART_1_Start();
    /* Place your initialization/startup code here (e.g. MyInst_Start()) */
    
    UART_1_UartPutString("hello world");
    
    char buffer[CY_FLASH_SIZEOF_ROW];
    for(uint i = 0; i<CY_FLASH_SIZEOF_ROW; i++)
        buffer[i] = 'A';
    
    int row = 1;
    CySysFlashWriteRow(row, &buffer);
    
    char buffer2[129];
    memcpy(buffer2, CY_FLASH_BASE + row*128, 128);
    buffer2[128] = 0;
    UART_1_UartPutString(buffer2);
    for(;;)
    {
       
        /* Place your application code here */
        
        char c;
        //c = UART_1_Get()
        c = UART_1_UartGetChar();
        
        if(c)
            UART_1_UartPutChar(c);

    }
}
