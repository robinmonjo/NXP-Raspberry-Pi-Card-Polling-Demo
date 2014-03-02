/*******************************************************************************
* Copyright (c), NXP Semiconductors Gratkorn / Austria
*
* (C)NXP Semiconductors
* All rights are reserved. Reproduction in whole or in part is
* prohibited without the written consent of the copyright owner.
* NXP reserves the right to make changes without notice at any time.
* NXP makes no warranty, expressed, implied or statutory, including but
* not limited to any implied warranty of merchantability or fitness for any
* particular purpose, or that the use will not infringe any third party patent,
* copyright or trademark. NXP must not be liable for any loss or damage
* arising from its use.
********************************************************************************
*
* Filename: main.c
* Processor family: ARM11
*
* Description: This file contains main entry.
*
*******************************************************************************/

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>

/* Configuration Headers */
/* Controls build behavior of components */
#include <ph_NxpBuild.h>
/* Status code definitions */
#include <ph_Status.h>

/* Reader Library Headers */
/* Generic ISO14443-3A Component of
 * Reader Library Framework */
#include <phpalI14443p3a.h>
/* Generic ISO14443-4 Component of
 * Reader Library Framework */
#include <phpalI14443p4.h>
/* Generic ISO14443-4A Component of
 * Reader Library Framework */
#include <phpalI14443p4a.h>
/* Generic MIFARE(R) Ultralight Application
 * Component of Reader Library Framework */
#include <phalMful.h>
#include <phalMfc.h>
/* Generic KeyStore Component of
 * Reader Library Framework */
/* In that example we don't use any
 * key. But we need the key components
 * for some function calls and you maight
 * need it when using crypto with
 * Ultralight-C cards. */
#include <phKeyStore.h>

#include <phpalSli15693.h>
#include <phpalSli15693_Sw.h>
#include <phpalFelica.h>
#include <phpalI14443p3b.h>

#define sak_ul                0x00
#define sak_ulc               0x00
#define sak_mini              0x09
#define sak_mfc_1k            0x08
#define sak_mfc_4k            0x18
#define sak_mfp_2k_sl1        0x08
#define sak_mfp_4k_sl1        0x18
#define sak_mfp_2k_sl2        0x10
#define sak_mfp_4k_sl2        0x11
#define sak_mfp_2k_sl3        0x20
#define sak_mfp_4k_sl3        0x20
#define sak_desfire           0x20
#define sak_jcop              0x28
#define sak_layer4            0x20

#define atqa_ul               0x4400
#define atqa_ulc              0x4400
#define atqa_mfc              0x0200
#define atqa_mfp_s            0x0400
#define atqa_mfp_s_2K         0x4400
#define atqa_mfp_x            0x4200
#define atqa_desfire          0x4403
#define atqa_jcop             0x0400
#define atqa_mini             0x0400
#define atqa_nPA              0x0800

#define mifare_ultralight     0x01
#define mifare_ultralight_c   0x02
#define mifare_classic        0x03
#define mifare_classic_1k     0x04
#define mifare_classic_4k     0x05
#define mifare_plus           0x06
#define mifare_plus_2k_sl1    0x07
#define mifare_plus_4k_sl1    0x08
#define mifare_plus_2k_sl2    0x09
#define mifare_plus_4k_sl2    0x0A
#define mifare_plus_2k_sl3    0x0B
#define mifare_plus_4k_sl3    0x0C
#define mifare_desfire        0x0D
#define jcop                  0x0F
#define mifare_mini           0x10
#define nPA                   0x11


// Forward declarations
uint32_t DetectMifare(void *halReader);
phStatus_t readerIC_Cmd_SoftReset(void *halReader);
uint8_t * read_mifare_ultra_light_user_data(phalMful_Sw_DataParams_t *alMful);

// Arrays

int main(int argc, char **argv)
{
    phbalReg_R_Pi_spi_DataParams_t spi_balReader;
    void *balReader;

    phhalHw_Rc523_DataParams_t halReader;
    void *pHal;
    phStatus_t status;
    uint8_t blueboardType;
    uint8_t volatile card_or_tag_detected;

    uint8_t bHalBufferReader[0x40];

    /* Initialize the Reader BAL (Bus Abstraction Layer) component */
    status = phbalReg_R_Pi_spi_Init(&spi_balReader, sizeof(phbalReg_R_Pi_spi_DataParams_t));
    if (PH_ERR_SUCCESS != status)
    {
        printf("Failed to initialize SPI\n");
        return 1;
    }
    balReader = (void *)&spi_balReader;

    status = phbalReg_OpenPort((void*)balReader);
    if (PH_ERR_SUCCESS != status)
    {
        printf("Failed to open bal\n");
        return 2;
    }

    /* we have a board with PN512,
     * but on the software point of view,
     * it's compatible to the RC523 */
    status = phhalHw_Rc523_Init(&halReader,
                                sizeof(phhalHw_Rc523_DataParams_t),
                                balReader,
                                0,
                                bHalBufferReader,
                                sizeof(bHalBufferReader),
                                bHalBufferReader,
                                sizeof(bHalBufferReader));
    pHal = &halReader;

    if (PH_ERR_SUCCESS != status)
    {
        printf("Failed to initialize the HAL\n");
        return 3;
    }

    /* Set the HAL configuration to SPI */
    status = phhalHw_SetConfig(pHal, PHHAL_HW_CONFIG_BAL_CONNECTION,
                               PHHAL_HW_BAL_CONNECTION_SPI);
    if (PH_ERR_SUCCESS != status)
    {
        printf("Failed to set hal connection SPI\n");
        return 4;
    }

    /**************************************************************************
     * Begin the polling
     *************************************************************************/
    printf("/****** Begin Polling ******/\n");

    for(;;)
    {

        /*
         * Detecting Mifare cards */
        if (DetectMifare(pHal))
        {
            /* reset the IC  */
            readerIC_Cmd_SoftReset(pHal);
        }
        else
        {
            printf("No card or Tag detected\n");
        }

        sleep(1);
    }

    phhalHw_FieldOff(pHal);
    return 0;
}

uint32_t DetectMifare(void *halReader) {
    phpalI14443p4_Sw_DataParams_t I14443p4;
    phpalMifare_Sw_DataParams_t palMifare;
    phpalI14443p3a_Sw_DataParams_t I14443p3a;

    phalMful_Sw_DataParams_t alMful;

    uint8_t bUid[10];
    uint8_t bLength;
    uint8_t bMoreCardsAvailable;
    uint32_t sak_atqa = 0;
    uint8_t pAtqa[2];
    uint8_t bSak[1];
    phStatus_t status;
    uint16_t detected_card = 0xFFFF;

    //Initialize the 14443-3A PAL (Protocol Abstraction Layer) component
    PH_CHECK_SUCCESS_FCT(status, phpalI14443p3a_Sw_Init(&I14443p3a, sizeof(phpalI14443p3a_Sw_DataParams_t), halReader));

    // Initialize the 14443-4 PAL component
    PH_CHECK_SUCCESS_FCT(status, phpalI14443p4_Sw_Init(&I14443p4, sizeof(phpalI14443p4_Sw_DataParams_t), halReader));

    // Initialize the Mifare PAL component
    PH_CHECK_SUCCESS_FCT(status, phpalMifare_Sw_Init(&palMifare, sizeof(phpalMifare_Sw_DataParams_t), halReader, &I14443p4));

    // Initialize Ultralight(-C) AL component
    PH_CHECK_SUCCESS_FCT(status, phalMful_Sw_Init(&alMful, sizeof(phalMful_Sw_DataParams_t), &palMifare, NULL, NULL, NULL));

    // Reset the RF field
    PH_CHECK_SUCCESS_FCT(status, phhalHw_FieldReset(halReader));

    // Apply the type A protocol settings and activate the RF field.
    PH_CHECK_SUCCESS_FCT(status, phhalHw_ApplyProtocolSettings(halReader, PHHAL_HW_CARDTYPE_ISO14443A));

    // Empty the pAtqa
    memset(pAtqa, '\0', 2);
    status = phpalI14443p3a_RequestA(&I14443p3a, pAtqa);

    // Reset the RF field
    PH_CHECK_SUCCESS_FCT(status, phhalHw_FieldReset(halReader));

    // Empty the bSak
    memset(bSak, '\0', 1);

    // Activate one card after another
	bMoreCardsAvailable = 1;
	while (bMoreCardsAvailable) {

		// Activate the communication layer part 3 of the ISO 14443A standard.
		status = phpalI14443p3a_ActivateCard(&I14443p3a, NULL, 0x00, bUid, &bLength, bSak, &bMoreCardsAvailable);

        if (status) {
            return false; //no card detected
        }
		
        printf("UID: ");
        uint8_t uid_index;
        for(uid_index = 0; uid_index < bLength; uid_index++) {
            printf("%02X ", bUid[uid_index]);
        }
        printf("\n");

        sak_atqa = bSak[0] << 24 | pAtqa[0] << 8 | pAtqa[1];
        sak_atqa &= 0xFFFF0FFF;

		// Detect mini or classic
		switch (sak_atqa) {
		  case sak_mfc_1k << 24 | atqa_mfc:
			detected_card &= mifare_classic;
		  break;
		  case sak_mfc_4k << 24 | atqa_mfc:
			detected_card &= mifare_classic;
		  break;
		  case sak_mfp_2k_sl1 << 24 | atqa_mfp_s:
			detected_card &= mifare_classic;
		  break;
		  case sak_mini << 24 | atqa_mini:
			detected_card &= mifare_mini;
		  break;
		  case sak_mfp_4k_sl1 << 24 | atqa_mfp_s:
			detected_card &= mifare_classic;
		  break;
		  case sak_mfp_2k_sl1 << 24 | atqa_mfp_x:
			detected_card &= mifare_classic;
		  break;
		  case sak_mfp_4k_sl1 << 24 | atqa_mfp_x:
			detected_card &= mifare_classic;
		  break;
		  default:
		  break;
		}

		if (detected_card == 0xFFFF) {
            //dealing with a mifare card
			sak_atqa = bSak[0] << 24 | pAtqa[0] << 8 | pAtqa[1];

			switch (sak_atqa) {
			case sak_ul << 24 | atqa_ul:
				printf("MIFARE Ultralight detected\n");
				detected_card &= mifare_ultralight;

                uint8_t * data = read_mifare_ultra_light_user_data(&alMful);

                uint8_t idx;
                for(idx = 0; idx < sizeof(data)/sizeof(uint8_t); idx++) {
                    printf("%02X ", data[idx]);
                }
                     
			break;
			case sak_mfp_2k_sl2 << 24 | atqa_mfp_s:
				printf("MIFARE Plus detected\n");
				detected_card &= mifare_plus;
			break;
			case sak_mfp_2k_sl3 << 24 | atqa_mfp_s_2K:
				printf("MIFARE Plus detected\n");
				detected_card &= mifare_plus;
			break;
			case sak_mfp_2k_sl3 << 24 | atqa_mfp_s:
				printf("MIFARE Plus detected\n");
				detected_card &= mifare_plus;
			break;
			case sak_mfp_4k_sl2 << 24 | atqa_mfp_s:
				printf("MIFARE Plus detected\n");
				detected_card &= mifare_plus;
			break;
			case sak_mfp_2k_sl2 << 24 | atqa_mfp_x:
				printf("MIFARE Plus detected\n");
				detected_card &= mifare_plus;
			break;
			case sak_mfp_2k_sl3 << 24 | atqa_mfp_x:
				printf("MIFARE Plus detected\n");
				detected_card &= mifare_plus;
			break;
			case sak_mfp_4k_sl2 << 24 | atqa_mfp_x:
				printf("MIFARE Plus detected\n");
				detected_card &= mifare_plus;
			break;
			case sak_desfire << 24 | atqa_desfire:
				printf("MIFARE DESFire detected\n");
				detected_card &= mifare_desfire;
			break;
			case sak_jcop << 24 | atqa_jcop:
				printf("JCOP detected\n");
				detected_card &= jcop;
				//PaymentCard(halReader, bUid);
			break;
			case sak_layer4 << 24 | atqa_nPA:
				printf("German eID (neuer Personalausweis) detected\n");
				detected_card &= nPA;
			break;
			default:
			break;
			}
		}
		

		// There is a MIFARE card in the field, but we cannot determine it
		if (!status && detected_card == 0xFFFF)
		{
			printf("MIFARE card detected\n");
			return true;
		}
		status = phpalI14443p3a_HaltA(&I14443p3a);
		detected_card = 0xFFFF;
	}
	return detected_card;
}

uint8_t * read_mifare_ultra_light_user_data(phalMful_Sw_DataParams_t *alMful) {
    uint8_t global_buffer[11 * 4]; //11 pages of 4 bytes
    uint8_t *cursor = global_buffer;
    memset(global_buffer, '\0', 11 * 4);
    phStatus_t status;

    //data on the card are located at address (pages) 04 to 0F (15)
    uint8_t buffer[4]; //will read 4 bytes per page
    int page;
    for(page = 4; page <= 15; page++) {
        memset(buffer, '\0', 4);
        PH_CHECK_SUCCESS_FCT(status, phalMful_Read(alMful, page, buffer)); //read the page

        printf("\nOn page \n");
        int idx = 0;
        for(idx = 0; idx < 4; idx++) {
            printf("%02X ", buffer[idx]);
        }
        memcpy(cursor, buffer, 4); //add it to glogab buffer
        cursor += 4;
        printf("After copy\n");
        for(idx = 0; idx < 11 * 4; idx++) {
            printf("%02X ", global_buffer[idx]);
        }
    }
    return global_buffer;
}

phStatus_t readerIC_Cmd_SoftReset(void *halReader) {
    phStatus_t status = PH_ERR_INVALID_DATA_PARAMS;
    switch (PH_GET_COMPID(halReader)) {
        case PHHAL_HW_RC523_ID:
            status = phhalHw_Rc523_Cmd_SoftReset(halReader);
        break;
    }
    return status;
}

