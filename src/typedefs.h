/*
 * Project:			Malflare
 * Authors:			Dominic Fischer / Daniel Jordi
 * Date:			16.03.2011
 */

#ifndef TYPEDEFS_H_
#define TYPEDEFS_H_

/**
 * Some default define's to make coding more comfortable
 */
#define false 0
#define true 1
#define null 0

#ifndef NO_DEFS
// Workaraound for doublicates in temu includes
typedef unsigned char uint8; // 1byte
typedef unsigned short uint16; // 2byte
typedef unsigned int uint32; // 4byte
#endif

/**
 *  IDS types
 */

/**
 * \brief Type for eax register
 */
#define EAX 0x00

/**
 * \brief Type for ebx register
 */
#define EBX 0x01

/**
 * \brief Type for ecx register
 */
#define ECX 0x02

/**
 * \brief Type for edx register
 */
#define EDX 0x03

/**
 * \brief Type for esi register
 */
#define ESI 0x04

/**
 * \brief Type for edi register
 */
#define EDI 0x05

/**
 * \brief Type for esp register
 */
#define ESP 0x06

/**
 * \brief Type for ebp register
 */
#define EBP 0x07

/**
 * \brief Type for eflags register
 */
#define EFLAGS 0x0E

/**
 * \brief End of registers marker, only internally used
 */
#define REG 0x0F //<-- END OF TV

/**
 * \brief Type for memory
 */
#define MEM 0x10

/**
 * \brief Type for opcodes (not used yet)
 */
#define OPC 0x20

/**
 * \brief Type for strings (not used yet)
 */
#define STR 0x30

/**
 * \brief Type for basic blocks (not used yet)
 */
#define BASIC_BLOCK 0xE0

/**
 * \brief End of IDS-chain
 */
#define END 0xFF

/**
 * \brief Stores the data of a cpu state. length and offset are only provided by type MEM
 */
typedef struct {
	uint8 type;
	void *value;
	uint32 length;
	uint32 offset;
} DATA;

/**
 * \brief Stores a cpu state of a given moment.
 */
typedef struct {
        uint32 eip;
        uint32 data_length;
        DATA data[];
} CPU_STATE;

/**
 * \brief MFT Handler
 */
typedef struct {
        FILE *info;
        FILE *idt;
        FILE *ids;
} MFT_H;

/**
 *  \brief Magic byte to identify a info file
 */
#define MFT_ID "MFT"

/**
 * \brief Current MFT version
 */
#define MFT_VERSION 1

/**
 * \brief Constant for 32bit register size (currently no meaning)
 */
#define MFT_REG32 0

/**
 * \brief Constant for 64bit register size (currently no meaning)
 */
#define MFT_REG64 1

/**
 * \brief Header information stored in the info file
 */
typedef struct {
	char id[3];
	uint8 version;
	uint8 reg_len;
} MFT_INFO;


/**
 * \brief IDT definition. Stores eip and a ids offset.
 */
typedef struct {
	uint32 eip;
	uint32 idso;
} MFT_IDT;

/**
 * \brief Value for MFT_IDT->idso if there is no ids offset linked
 */
#define NO_IDS 0xFFFFFFFF

#endif /* TYPEDEFS_H_ */
