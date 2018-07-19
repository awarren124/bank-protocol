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
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>

int main (void)
{
    CyGlobalIntEnable;      /* Enable global interrupts */
    
    /* Place your initialization/startup code here (e.g. MyInst_Start()) */
    
    UART_Start();
    UART_PutString("hello world\n");
    
    //RSA
    int ret = 0;
    
    mbedtls_pk_context pk;
    mbedtls_pk_init( &pk );
    
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    size_t olen = 0;
    
    //Card information
    
    long long exampleCreditCardNumber = 4753245442839561;
    char * exampleExpirationDate = "0922";
    
    for(;;)
    {
        /* Place your application code here */
    }
}
