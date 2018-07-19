/*******************************************************************************
* File Name: SPI_miso_s.h  
* Version 2.20
*
* Description:
*  This file contains the Alias definitions for Per-Pin APIs in cypins.h. 
*  Information on using these APIs can be found in the System Reference Guide.
*
* Note:
*
********************************************************************************
* Copyright 2008-2015, Cypress Semiconductor Corporation.  All rights reserved.
* You may use this file only in accordance with the license, terms, conditions, 
* disclaimers, and limitations in the end user license agreement accompanying 
* the software package with which this file was provided.
*******************************************************************************/

#if !defined(CY_PINS_SPI_miso_s_ALIASES_H) /* Pins SPI_miso_s_ALIASES_H */
#define CY_PINS_SPI_miso_s_ALIASES_H

#include "cytypes.h"
#include "cyfitter.h"
#include "cypins.h"


/***************************************
*              Constants        
***************************************/
#define SPI_miso_s_0			(SPI_miso_s__0__PC)
#define SPI_miso_s_0_PS		(SPI_miso_s__0__PS)
#define SPI_miso_s_0_PC		(SPI_miso_s__0__PC)
#define SPI_miso_s_0_DR		(SPI_miso_s__0__DR)
#define SPI_miso_s_0_SHIFT	(SPI_miso_s__0__SHIFT)
#define SPI_miso_s_0_INTR	((uint16)((uint16)0x0003u << (SPI_miso_s__0__SHIFT*2u)))

#define SPI_miso_s_INTR_ALL	 ((uint16)(SPI_miso_s_0_INTR))


#endif /* End Pins SPI_miso_s_ALIASES_H */


/* [] END OF FILE */
