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
    for(;;)
    {
        UART_1_UartPutString("that was frustrating");
        /* Place your application code here */
        /*char c = UART_UartGetChar();*/

    }
}
