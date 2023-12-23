// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************************************
 Description of the OEM firmware layout
***************************************************************************************************/
/*
The OEM firmware has the following layout, the example is based on M32_REVA_FIRMWARE_v1.00B34.bin.
----------------------------------------------------------------------------------------------------
| Address (hex)    | Length (hex) | Data
|------------------|--------------|-----------------------------------------------------------------
| 0x00000000       | 0x10         | Header for SHA512 verification of the image, details below.
| 0x00000010       | 0x10         | Header for AES-CBC decryption of the image, details below.
| 0x00000020       | 0x20         | IV for AES-CBC decryption as ASCII string.
| 0x00000040       | 0x01         | Constant 0x0A (LF)
| 0x00000041       | 0x08         | ASCII "Salted___" without trailing \0
| 0x00000049       | 0x08         | The salt for the firmware decryption.
| 0x00000051       | variable     | The encrypted data.
| variable         | 0x100        | The signature for the SHA512 verification.
----------------------------------------------------------------------------------------------------

After decrypting the encrypted data (starting at 0x00000051 in the OEM firmware image),
there can be one or more partitions in the decrypted image. In the example below, there is
a second partition, but it's optional.
Overall, there is the following layout (offset 0x00000051 not included):
----------------------------------------------------------------------------------------------------
| Address (hex)    | Length (hex) | Data
|------------------|--------------|-----------------------------------------------------------------
| 0x00000000       | 0x10         | Header for SHA512 verification of the image, details below.
| 0x00000010       | 0x50         | Header of the first partition to flash, details below.
| 0x00000060       | variable     | The decrypted data of the first partition.
| variable         | 0x50         | Header of the ssecond partition to flash, details below.
| 0x00000060       | variable     | The decrypted data of the second partition.
| variable         | 0x100        | The signature for the SHA512 verification.
----------------------------------------------------------------------------------------------------

A header for SHA512 verification has the following layout:
----------------------------------------------------------------------------------------------------
| Address (hex)    | Length (hex) | Data
|------------------|--------------|-----------------------------------------------------------------
| 0x00000000       | 0x04         | ASCII "MH01" without trailing \0
| 0x00000004       | 0x04         | Length of the data to verify (little endian format)
| 0x00000008       | 0x04         | Constant 0x00 0x01 0x00 0x00
| 0x0000000C       | 0x02         | Constant 0x2B 0x1A
| 0x0000000E       | 0x01         | Byte sum of byte 0-13
| 0x0000000F       | 0x01         | XOR of byte 0-13
----------------------------------------------------------------------------------------------------

A header for AES-CBC decryption has the following layout:
----------------------------------------------------------------------------------------------------
| Address (hex)    | Length (hex) | Data
|------------------|--------------|-----------------------------------------------------------------
| 0x00000000       | 0x04         | ASCII "MH01" without trailing \0
| 0x00000004       | 0x04         | Constant 0x21 0x01 0x00 0x00
| 0x00000008       | 0x04         | Length of the data to decrypt (little endian format)
| 0x0000000C       | 0x02         | Constant 0x2B 0x1A
| 0x0000000E       | 0x01         | Byte sum of byte 0-13
| 0x0000000F       | 0x01         | XOR of byte 0-13
----------------------------------------------------------------------------------------------------

A header of the decrypted firmware image parition has the following layout:
----------------------------------------------------------------------------------------------------
| Address (hex)    | Length (hex) | Data
|------------------|--------------|-----------------------------------------------------------------
| 0x00000000       | 0x0C         | ASCII "DLK6E6010001" without trailing \0
| 0x0000000C       | 0x04         | Constant 0x00 0x00 0x3A 0xB5 (differs in different FW versions)
| 0x00000010       | 0x0C         | Hex 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01 0x00
| 0x0000001C       | 0x04         | Constant 0x4E 0xCC 0xD1 0x0B (differs in different FW versions)
| 0x00000020       | 0x04         | Erase start address of the partition (little endian format)
| 0x00000024       | 0x04         | Erase length of the partition (little endian format)
| 0x00000028       | 0x04         | Write start address of the partition (little endian format)
| 0x0000002C       | 0x04         | Write length of the partition (little endian format)
| 0x00000030       | 0x10         | 16 bytes 0x00
| 0x00000040       | 0x02         | Firware header ID: 0x42 0x48
| 0x00000042       | 0x02         | Firware header major version: 0x02 0x00
| 0x00000044       | 0x02         | Firware header minior version: 0x00 0x00
| 0x00000046       | 0x02         | Firware SID: 0x09 0x00
| 0x00000048       | 0x02         | Firware image info type: 0x00 0x00
| 0x0000004A       | 0x02         | Unknown, set to 0x00 0x00
| 0x0000004C       | 0x02         | FM fmid: 0x60 0x6E. Has to be match the "fmid" of the device.
| 0x0000004E       | 0x02         | Header checksum. It must be set to that the sum of all words
|                                   in the firware equals 0xFFFF. An overflow will increase the 
|                                   checksum by 1. See function "UpdateHeaderInRecoveryImage".
----------------------------------------------------------------------------------------------------
*/
/***************************************************************************************************
 Includes
***************************************************************************************************/
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/***************************************************************************************************
 Defines
***************************************************************************************************/
/*
* Length of the header in a firmware image which can be used in the recovery web interface.
*/
#define M32_FIRMWARE_UTIL_FW_HEADER_LENGTH          (80u)


/**
 * Maximum number of partitions in a recovery image. Assume there is a maximum of 16.
 * Currently M32 has 13 partitions, so 16 should be sufficient overall.
*/
#define M32_FIRMWARE_UTIL_MAX_PARTITIONS            (16u)

/*
* Offset of the entry "data length" in the header of a firmware image 
* which can be used in the recovery web interface.
*/
#define M32_FIRMWARE_UTIL_FW_DATA_LENGTH_OFFSET     (0x2C)

/*
* Offset of the entry "data checksum" in the header of a firmware image 
* which can be used in the recovery web interface.
*/
#define CHECKUM_PATCHER_DATA_CHECKSUM_OFFSET        (0x0E)

/*
* Offset of the entry "header checksum" in the header of a firmware image 
* which can be used in the recovery web interface.
*/
#define CHECKUM_PATCHER_HEADER_CHECKSUM_OFFSET      (M32_FIRMWARE_UTIL_FW_HEADER_LENGTH - 2u)

/*
* The length of headers in the OEM images.
*/
#define M32_FIRMWARE_HEADER_LENGTH                  (16u)

/*
* The length of signatures in the OEM images.
*/
#define M32_FIRMWARE_SIGNATURE_LENGTH               (256u)

/*
* The length of the initialization vector in the OEM images.
* It's a 32 bytes string for the IV plus a trailing 0x0A.
*/
#define M32_FIRMWARE_INITIALIZATION_VECTOR_LENGTH   (33u)

/**
 * 0x08 bytes for ASCII "Salted__" without trailing \0
 * 0x08 bytes for the salt
*/
#define M32_FIRMWARE_SALT_INFO_LENGTH               (16u)

/**
 * Length of the data which are required for decryption of the image.
 * 0x20 bytes IV for AES-CBC decryption as ASCII string
 * 0x01 byte for terminating the IV ASCII string with 0x0A (LF)
 * 0x08 bytes for ASCII "Salted__" without trailing \0
 * 0x08 bytes for the salt
*/
#define M32_FIRMWARE_DECRYPTION_INFO_LENGTH \
  (M32_FIRMWARE_INITIALIZATION_VECTOR_LENGTH + M32_FIRMWARE_SALT_INFO_LENGTH)

/**
 * Enable writing of debug files.
*/
#define M32_FIMRWARE_UTIL_ENABLE_DEBUG_FILES
/***************************************************************************************************
 Types
***************************************************************************************************/
typedef struct
{
  const char* Name;
  const char* Description;
  const char* RecoveryHeaderStart;
  const char* FirmwareKey;
  const char* PrivateKey;
  const char* PublicKey;
  const char* Passphrase;
} M32FirmwareUtilDeviceInfoType;

/**
 * Function pointer type for operations in M32FirmwareUtilOperationsType.
 * Arguments:
 * inputfile: FILE handle for the input file.
 * fileStatus: Input file stats.
 * oupufFile: Name of the output file.
 * device: Pointer to the structure containing device specific information.
*/
typedef int (*M32FirmwareUtilOperation)(FILE* inputFile, struct stat* fileStatus, const char* outputFile, const M32FirmwareUtilDeviceInfoType* device);

/**
 * Structure for maintaining command line arguments in this tool.
 */
typedef struct
{
  /**
   * The command line argument.
  */
  const char* Argument;
  /**
   * Descsription what the argument is used for.
  */
  const char* Description;
  /**
   * The function which will be executed for this argument.
  */
  M32FirmwareUtilOperation Operation;
  /**
   * The minimum expected input file size for this argument.
  */
  size_t MinimumFileSize;
} M32FirmwareUtilOperationsType;

/***************************************************************************************************
 Function prototpyes
***************************************************************************************************/
/*****************************************************************************************
 Main Operations
*****************************************************************************************/
static int UpdateHeaderInRecoveryImage(FILE* file, struct stat* fileStatus, const char* outputFile, const M32FirmwareUtilDeviceInfoType* device);
static int CreateFactoryImageFromRecoveryImage(FILE* file, struct stat* fileStatus, const char* outputFile, const M32FirmwareUtilDeviceInfoType* device);
static int DecryptFactoryImage(FILE* file, struct stat* fileStatus, const char* outputFile, const M32FirmwareUtilDeviceInfoType* device);

/*****************************************************************************************
 Signature APIs
*****************************************************************************************/
static int VerifySha512Signture(const uint8_t* buffer, const size_t bufferLength, const M32FirmwareUtilDeviceInfoType* device);
static int CreateSha512VerificatioinSignature(uint8_t* buffer, size_t imageSize, const M32FirmwareUtilDeviceInfoType* device);

/*****************************************************************************************
 AES128 CBBC APIs
*****************************************************************************************/
static int DecryptAes128Cbc(const uint8_t* encryptedData, const size_t encryptedLength, uint8_t* outputBuffer, const char* keyString, const uint8_t* ivHex);
static int EncryptAes128Cbc(const uint8_t* plainData, const size_t plainDataLength, uint8_t* outputBuffer, uint8_t* saltBuffer, const char* keyString, const uint8_t* ivHex, int* encryptedDataLength);

static int GetDataLengthFromVerificationHeader(uint8_t* header, size_t* dataLength);
static int GetDataLengthFromEncryptionHeader(uint8_t* header, size_t* dataLength);
static int ConvertAsciiIvToHexArray(const uint8_t ivAscii[AES_BLOCK_SIZE * 2], uint8_t ivHex[AES_BLOCK_SIZE]);
static int CreateAes128CbcEncryptionHeader(uint8_t* buffer, size_t imageSize);
static int CreateSha512VerificatioinHeader(uint8_t* buffer, size_t imageSize);
static int WriteBufferToFile(const uint8_t* buffer, const size_t bufferSize, const char* outputFile);
static int WriteDebugBufferToFile(const uint8_t* buffer, const size_t bufferSize, const char* outputFile);
static int WriteAes128CbcIvToBuffer(uint8_t* buffer, const uint8_t* iv, const size_t ivLength);
static void PrintUsage(char* programName);
static void PrintOpenSSLError(const char* api);

/*****************************************************************************************
 Checksum calculation
*****************************************************************************************/
static void Caclulate16BitSum(const char* name, uint32_t partitionIndex, uint8_t* buffer, size_t bufferLength, uint8_t* checksumBuffer, bool inverted);
/***************************************************************************************************
 Constants
***************************************************************************************************/
const M32FirmwareUtilOperationsType M32FirmwareUtilOperations[] =
{
  {
    "--UpdateFirmwareHeader",
    "Updates data length information and checksum in an existing header in a recovery image",
    &UpdateHeaderInRecoveryImage,
    M32_FIRMWARE_UTIL_FW_HEADER_LENGTH
  },
  {
    "--CreateFactoryImage",
    "Create a factory image from a recovery image",
    &CreateFactoryImageFromRecoveryImage,
    /* At least 1kB of payload expected */
    1024
  },
  {
    "--DecryptFactoryImage",
    "Decrypts a factory image",
    &DecryptFactoryImage,
    /* Signature and header for inner and outer image plus at least 1kB payload */
    2 * (M32_FIRMWARE_SIGNATURE_LENGTH + M32_FIRMWARE_HEADER_LENGTH) + 1024
  }
};

const int M32FirmwareUtilOperationsLength = 
  sizeof(M32FirmwareUtilOperations) / sizeof(M32FirmwareUtilOperationsType);

const char M30PrivateKey[] = R"(
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,8A0BF905B77DC148004E713C828DC660

iFD5lI2LhcgxPVAuBU5E/PMABnLNTzasvFfonExni1D2NdTxATjiA88Urk0+cSiw
Tb6Z9a8ODVw6jX2NiH5rm7TzSDUoaF9y/d+67EKMpyz/+vYgl9ZtHwesi5L5Hn+0
0ukeL1IgTlZX3SzbFAyRHDOmt/AJBc1lhrB4wSIJkMggZxF3s+EHLjf5I0Mo6rvQ
sFyYJ28gy5CFvwN+xIcy3DRASdKjl0PIRCUPaJYdRkF0TjiyVMvy17tiI/ZAuMdJ
5FwzPg7VksHFJ08Vvd96/1IW+Z5f3RIya00q+4+eH6G4ksmZiWvd0Gyy9U8yt/TW
yb7h7LxGvaeGhPeEIdjQp90dMBDo+JdsVXbDIhI83z6NR0W+QV3db1lIUXapV1a0
NH6KgFe40/Z/foSqX6G0stbnmVZHEEtKqDEilFNImORJQDJyeC/OvKqWx+yF9Xh4
ML/WHMBW1XJQBnJgng/Y690H2JUa6M/d6ovyxZV50ANMFlurGJMXCVV8Li2kC87C
C/2Kcajl2xEi4J0zRgqblZ6C5IRaSuaYPSdSjVXScz/qRG2CE5uAEXfhMy9cBU5E
xeCdBSHktTTB3FYvUGFEz3oKzakLwi1iUKMM7uQhgehP+DV/TD1bMm3WT25rNXi8
m+Vq9Ieu+ObqTqGX/FSa3QxQx8WbO0YGW0l/46JzbusiP+mGxZH94r+CtB+3TflS
9xrXx+uV6UKNHWFIaKAlVYTCou6SUYGENGSTOEN2v/oPUfN2gUuh31p9muJXpA6t
Wd8oEcOCMk9FSN12TQ/3HK2tXB/DoRQRwDu837Bk4Fh0lQQy9DjBo9kPC5ZTlXN4
6MB+E3P72MuSsLOCAkcD0kJ6Uug1bM8rNqkEevsi7UPyNtilharewhHImG1oou2q
OwdeweLZlDE/nXb+gmTkhzOa0zDtZck4TBotwxCmvBU+CEXvLpAeqyaHAP4NKYMc
QGDqYMAVyxH2hNtXXSkpDy6ojSTCAamZBtS/3tE1C7YkSWHedeoPmkUMxvgcAwH/
E4piO5KJ7PtYEkFbZ5Fo63cHvnVndW1F0/INn3GsmiNerSa75u2VUWOZ0m0fg2nR
L18hu9CsxcBB9wIPEEVVkGmvGIZgYZz9IuntLmO5Njr1k8PBoTyLmM55NRS3yXvA
/MleG6nkUdZ+pemhhUnoST5JIf8qEZuwpZ1bvx095ZJsDxIUbQqBBW+cKgIi2SCW
OP8qltuE0hfG/inOerWN9GDrXwb9C3/hTkyb+yecCAQGbu5fkHYGnniVUFgUu7dd
Kv/Aorn3I6HMFBk2+XoH5BMS+It17wORVMOfXHdmyem0w6SjLdciuoE869mvkk22
uNvC9GS+puyqxae1SMorH5DOBLCmxgYrfu/+WOfjktxLOYmvguQUzJ2MfuejHejd
XPDLYXZnqBxDq4jFkuz/lBy+niq/m2jqlVLhTxKU98CkeYhhdoDPRqolZu15lULQ
ghDShGIkpLoRJD42+6Ddhm0i7TmubNPtB/AwOie2tkyYNf+vkZZLL0UyHXhJJTeb
UA5Bcn8QXE1gzoqLedid5TKFUss3hUrqwmp7sbhycRUdOZaty9LwS71Ogh0YQ048
-----END RSA PRIVATE KEY-----
)";

const char M30PublicKey[] = R"(
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvIj1OH7L1Wza1aa+ZJl1
Tb2+6jFxTC4fQhWF+tuHngbAD2YEJVVliQZ27biYR+AOOyKKrp3X6yEZQ28iwio2
qmvgCrs+UMftKZkozbD+A8JKmrEx2RRloIpFWHEQCgw1JWkWngC2vguoSbP8rtlB
Qeuevp+oa0fewZd4iPG37b8+dvRucaDyDJgrXXosCTKQVeuGdqF/l6jIDEzLX9c5
A2k2zBwhTzRUbwrhMF8FPhv8pxN3+YXx75vfYZnw3/dasu6RT2NyWVKlRt86HbfF
LvNSHDaUNDa5gjmZ4NTm0uR39X15fO+vAsqQBRnURN1uaJzJRQWazMlKtHR5WfHO
2QIDAQAB
-----END PUBLIC KEY-----
)";

const char M32PrivateKey[] = R"(
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,D7727E22F450CD0662339F7281626762

kJW0MGY6OnlxhnUPqwmWC2nTuYMrbKlSnQ8vHzL5XY7W6XoJQD9qZiP7YmoMB+Jd
lgoJ/GMnok+il2/0cTQEkLdOghsw3KfvVRBSgSh77imOSugpq6IaSZZsekwQFNYn
bsY+Yo2C6KF48a1oO9i4vPCmxqapNBINUtrjo2YHIkPo5SGdgfGg4E4vZyuvD5+q
AJ7X4qaz78WpezHKod7aaE7tAiX0+iP+H59rUnSpTh8f3/1jJLAxZEqBX8deDl/m
B51GeOIMArSzqUW4WHBPBXfiJTCL5ql63wgFfTE9gj3VATA3CoOQyXCDAR12Aihc
xCSFbATOOmzZxr0XYhP9QUmkVY6Pa14rg4HsxbwxzhBtM9SMgOI2ZNRuNO5nLab8
+Rro8NkDrbJw2uh6lHKmlfmW7nfrKnHdxqoI6eugRGPKG093+qZfCYJw5Gme9bmM
Cz7nFSwP8M9Zc2QFoo20x86NFxZOCkJwy0+9FsGPFYIxT/kZt+cS2votpp7kQizU
Ij8Zs6x8HCflG5EClpp5K2ZtZg/C8g34R5KBMae4B8n+l4YSeUfq/r7XKXoLFT/h
lvUlfC3pb0w1bpxSTtD0g5rJLdHPYQVNUAla6igqdIGN+nMpa+ug+vB7aA/DmFUz
ARDDr4n+GhScVmCjpK1/bO7sBp4XNU9u2ZJ6XmGPtQYGJX0uwQDK5F8+kV+bLdb7
3R7od2unRYONDhFIje6CQIZwzPdrZILs+z7kduP/ohyJJ0F3c4FF0R2FADQCfgu1
Zbk7egIMu8DD7m/ZK1R5PETa+IAwhclOngcELOb5TScNdBs1EQUtGhiRI3KxFX1H
PVjbONcHdxLmatVai0AR5OJHdQWBbS4Ely8PIl6IQbG0rPh5Sel7YpMLTIF/QEvK
NKseRQywV7n69j2QUjMqhDJYp66i53u/UbK2ceoeqf2LkRYWWwyUS7wRsColhwxv
LQjrmy1Ck5yXyd3hAXakOmBytGneuUbpUixmoyP05+vISo5cmTcxFhoAcm6nMFvT
0J6rIJrDJojTLm2WG3Fn3oAmDzhmAr8bQu1fu43jFqCMUjeirDmMzlzfiP6PeNE6
7mygxuqprynPz5lZBDuNOHZ/IyyNYIJkuFEzCYrsi6TlYRksmwlzgdm6xwb/3kgX
jgSU/BHFSbjQ6HkQ0Z6C6kt4R6Q1MCyMfqGzhmwK3XCIa8m9UfYc5m9jCtTECCX9
FDgOot7Z1cuPfI39k/qjedz0z8/3HWqmw5sgZJswaJS25N3oj7IV2sYqbqApJpaR
t0yfOjs3daJxiuMktcGzMIs+uIBGBPLvl3psZ2B8idcFJfxXjQ+JaVEWSAB8WGRr
QjIzqlaDdg6/+0iL+R5C6dpyKcpt7mAl1sRtW4KpYNLHnr3rc6PhS9ezLQ7IH7Cp
96pKlUZ70XGBOcDdH4uUTiheSbswUj3CIBGj2mvXcnMvGLTq6aoJT1rNr8Gc7Mrd
B16iFKjfVPvRtNLkjxOfGkt7YaMhT6olBCWOyVd276+m1fRF9c1KvtFJEYw/ebnD
FxqYe2clwJkpuUBJe/8dd6ZI+lJMAh4jH8KNHDomtsEuAjAO3Hi4KnA4oS3WEgRm
-----END RSA PRIVATE KEY-----
)";

const char M32PublicKey[] = R"(
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2H2vHvLcNi7uImWDJm3A
eXMV+Nzma0sSHaNjH/fo0LrsDjJnRA23kkcaw1L1z3Ts5qD60Dd0yuHD9xrYgsLc
2IEEHd8oBv+JOJzsqIOdcPCK47sKFqqd0R7ugz5ZfxHVx4K9ZufMO1g9WRe9Us1+
ULSACIBTJW7Zv7XFkInMPzJCzbWa05NozyP4NyBsqt3zaysjfAP6G7kHf+J60tCU
maOH1T/XnqeogzaDZ5FrQHIKMPOXLXuuSumHzr33XNo2vfiUEXIcaH+01NNfBEAa
FYqnIeHEm/eCVdwbL5qr/b+A70Co05tKNlr1fTnUBslAJX+GZ8+oj6JP6dV8B8sE
JwIDAQAB
-----END PUBLIC KEY-----
)";

const char M60PrivateKey[] = R"(
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,43936836BBBCB8B6BE9CBE8248796F8E

ieaLoSaqikjLtUcCkXaRqiTnNSt4Wf03r5OeA55/ioquzQTg83cJP65PHELRiv7v
PbQdCBBTQXmKbUZNbD8rF8HfT5jVBTvOcfJqzh9DsbqJndf4YHXPnHdCoJ2H7jqb
FPoKJe9G9dSc5ddYUuQi2Jfk/iRhkgTxwiTMJfy3B0yScDOZL8D3slBZUrT2tOdw
qLrKMtHqqCo1BrHy75xOwFH+bvFW9AxW9uuH+RvTm+wfHxvHsmghklO9HQvzJh5+
eQ6fW51sZ9zBeB75kbfDhOPH/EDOV9ANKqe4jbwBWjl/Ps2ABkSUuOrfXklNhJuS
gBfalVDhiZVIIuQTWhqbg7dOnxOR813EdvvKsovBZr78U2DroeBPS9cG4lOQEOvI
RDkA7eJt3/yNeuZHlQjL8wRAW8NEsU2UnzjUU+HaNmneT0rs8b1Roe9S39BHV8fF
4HwE2vhtGv6kxY/UQG7tpv6SKyT3Mso1UJ82YwF8wHsrVn2L+fGccj2AFpG0NGF5
ewkCb2ijVV1qoC1GbZWZgFil/5aCqFUnvGD6aCuFfxxr6Vk4iQwNqffMBbaEqStB
eTX0up5LKU9UhhmKkAitK3FbfqezLkvlErM18zknyWr/SDKcZm81Ay30xmJWqE14
pqCqXM8yPupzCiSfZz62Zit0M1pV5SHdm7zUlSv5f4jI4LNku26KjcHvNzMHHxaw
wN0blm7x5GYbJY7V8MY4OmZxbWCYJnNz5QV0XVD8HoNS/KuRrm5avFEOq/OH1WwJ
jZzq29Bp25/acfyubEDKz0sd2u5wiC5biesnHJObdblEVuUtgM3J5n8+KwgXn5GM
Pjf79VBxtVQ61Zv79Q4liz8F5UMJzb3hck2bK0/rIxwUDSNX6Y27X9Yxgsq8ZHRF
WFc33vHQ8Em5CglIXgRBr03wvzaGMCa+mVkwKpwFBm1QTaNSIoDXZz6H/6Xt5RWg
+IVjF7h8ysTN9xbENwmDZOWYRN9JGf455qpmAR/G7JeQuiiP06y4aIxN9reG3w40
rusqo0TIp5Gr125IaTlgAR5GyuX8DiRQ5sqsDAGAJZ0x+SvxFeQSgQo/BwkgXb9d
YKeh2HeOSioBwlBTDSb7ev/xT0autGhmbnviEh0Np3rkQf6qAe720WniLCuNamR9
5X9B6FPhb85yCvPtqAcQOHagVuRbl19lFjlAdO7qA+W0ioaSrSLAWRhOa/iqhi+S
mNqZQFnuCXYBOquKZumW5GWuGhuFcaRsqQuHRWaJDuuAhH8xaMISD2hQ5/oJqqaG
/PFB+Ez+zsSffpY+HzHDo8QHNfpizI3sTKXiMRkaN7cCr09nI+A9YKvycIdGLqC+
cympPmboygv5rWsROyWfPdophZ2pBJ0oZggnzNTNm6Njztt1Wyoid0dN4Y74dO1F
krNHmtHpTlhXrO0jZUVpdwkUPVI9EhZxrKwDI9HQIqqZkeM3XhFlz6ob8Gtpr9zw
6ERdBBpxkn1a90kzj3YInS6G2uUOJ2X/rjO8vRSkLXyskpUKFzK2GhbKduFWEc3R
Rs2yj0p2ifYjwSiZFYN1Hrd5o039DrNQQ3zxBtlWWTOY1lXXJJO/djxUfTBJFlEC
-----END RSA PRIVATE KEY-----
)";

const char M60PublicKey[] = R"(
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2jKyYjx2yU97eXkYbRiA
6XtiCTIfZDLBgI8RHa3j33RiNKnEuYqjZtRn0UG9ZjBKcKFPKgxDh06Q8wGxEJXJ
HpmQiPGdb+cG/+2VWr5+FF/tofRfh8jPzREBqcc59H05e6ZcMbVfRoDOObA+xE9R
IbM6Io9uJg6M8/5sOpD01N7HlGPeMtcuTucoEsgdVWJCqBA4u1q941TAg131rzXO
LM2+LSNO5yhNc+hRsACSlIcBbIgRC6DoDXO/AoM5nyQMDFPDdaT8Cs0omHzINzYj
G0gXMwkMuIW1Tz0ZNobAifB9ReNNLn4+wxCXTSjS15hYs4rJrJqL+8kcHdtDkceP
SwIDAQAB
-----END PUBLIC KEY-----
)";

const M32FirmwareUtilDeviceInfoType M32FirmwareUtilDeviceInfos[] = 
{
  {
    "M30",
    "D-Link AQUILA PRO AI AX3000 Smart Mesh Router",
    "DLK6E6110001",
    "b4517d9b98e04d9f075f5e78c743e097",
    M30PrivateKey,
    M30PublicKey,
    "wrpd"
  },
  {
    "M32",
    "D-Link EAGLE PRO AI AX3200 Mesh-System",
    "DLK6E6010001",
    "6b29f1d663a21b35fb45b69a42649f5e",
    M32PrivateKey,
    M32PublicKey,
    "wrpd"
  },
  {
    "R32",
    "D-Link EAGLE PRO AI AX3200 Smart Router",
    "DLK6E6015001",
    "6b29f1d663a21b35fb45b69a42649f5e",
    M32PrivateKey,
    M32PublicKey,
    "wrpd"
  },
  {
    "M60",
    "D-Link AX6000 Wi-Fi 6 Smart Mesh Router",
    "DLK6E8202001",
    "c5f8a1e22f808abc84f2e4a6fa5f10bb",
    M60PrivateKey,
    M60PublicKey,
    "wrpd"
  }
};

const int M32FirmwareUtilDeviceInfosLength = 
  sizeof(M32FirmwareUtilDeviceInfos) / sizeof(M32FirmwareUtilDeviceInfoType);

/**
 * String which indicates the start of a header for SHA512 verification or AES 128 CBC encryption.
 * Note: The trailing \0 is not present in the firmware data.
*/
const char* M32FirmwareUtilHeaderStart = "MH01";

/***************************************************************************************************
 Variables
***************************************************************************************************/
static bool M32FirmwareUtilWriteDebugFiles = false;

static char* M32FirmwareUtilDebugTargetFolder = NULL;
/***************************************************************************************************
 Implementation
***************************************************************************************************/
int main(int argc, char *argv[]) 
{
  int status = 1;
  if ((argc != 5) && (argc != 7))
  {
    PrintUsage(argv[0]);
  }
  else
  {
    char* deviceArg = argv[1];
    char* operationArg = argv[2];
    char* inputFileArg = argv[3];
    char* outputFileArg = argv[4];

    const M32FirmwareUtilOperationsType* entry = NULL;
    for (int i = 0; i < M32FirmwareUtilOperationsLength; i++)
    {
      if (strcmp(M32FirmwareUtilOperations[i].Argument, operationArg) == 0)
      {
        entry = &(M32FirmwareUtilOperations[i]);
      }
    }

    const M32FirmwareUtilDeviceInfoType* device = NULL;
    for (int i = 0; i < M32FirmwareUtilDeviceInfosLength; i++)
    {
      if (strcmp(M32FirmwareUtilDeviceInfos[i].Name, deviceArg) == 0)
      {
        device = &(M32FirmwareUtilDeviceInfos[i]);
      }
    }

    if ((argc > 6) && (strcmp("--debug", argv[5])== 0))
    {
      M32FirmwareUtilWriteDebugFiles = true;
      M32FirmwareUtilDebugTargetFolder = argv[6];
    }

    if ((entry == NULL) || (device == NULL))
    {
      PrintUsage(argv[0]);
    }
    else
    {
      FILE* file = NULL;
      
      int fileDescriptor;
      struct stat fileStatus;

      if ((file = fopen(inputFileArg, "rb+")) == NULL)
      {
        printf("Unable to open file %s\n", inputFileArg);
      }
      else if ((fileDescriptor = fileno(file)) == -1)
      {
        printf("Unable to get file descriptor for %s\n", inputFileArg);
      }
      else if ((fileDescriptor = fstat(fileDescriptor, &fileStatus)) == -1)
      {
        printf("Unable to get file status for %s\n", inputFileArg);
      }
      else if (fileStatus.st_size < entry->MinimumFileSize)
      {
        printf("File %s is smaller than %zu bytes\n", inputFileArg, entry->MinimumFileSize);
      }
      else
      {
        status = entry->Operation(file, &fileStatus, outputFileArg, device);
      }

      if (file != NULL)
      {
        fclose(file);
        file = NULL;
      }
    }
  }

  return status;
}


static void PrintUsage(char* programName)
{
  printf("Usage: %s <Device> <Operation> <InputFile> <OutputFile> [--debug] <Directory>\n", programName);
  
  printf("\n<Device> can be one of the following:\n");
  for (int i = 0; i < M32FirmwareUtilDeviceInfosLength; i++)
  {
    printf("%s: %s\n",M32FirmwareUtilDeviceInfos[i].Name, M32FirmwareUtilDeviceInfos[i].Description);
  }

  printf("\n<Operation> can be one of the following:\n");
  for (int i = 0; i < M32FirmwareUtilOperationsLength; i++)
  {
    printf("%s: %s\n",M32FirmwareUtilOperations[i].Argument, M32FirmwareUtilOperations[i].Description);
  }

  printf("\nThe argument \"--debug\" is optional.\n");
  printf("If present, debug files will be written to the directory specified by <Directory>\n");
}

/// @brief
///   Updates the block length and the checksum in a recovery image header.
/// @param file
///   The FILE handle of the input file.
/// @param fileStatus
///   The file status of the input file.
/// @param outputFile
///   The name of the output file.
/// @return
///   The function returns 0 if the update of the header was successful; otherwise 1.
static int UpdateHeaderInRecoveryImage(FILE* file, struct stat* fileStatus, const char* outputFile, const M32FirmwareUtilDeviceInfoType* device)
{
  int status = 1;
  unsigned char* buffer = NULL;
  
  if ((buffer = malloc(fileStatus->st_size)) == NULL)
  {
    printf("Unable to allocate buffer to read input file\n");
  }
  else if (fread(buffer, 1, fileStatus->st_size, file) != fileStatus->st_size)
  {
    printf("Unable to read data from input file\n");
  }
  else
  {
    uint32_t partitionCount = 0;
    size_t headerAddresses[M32_FIRMWARE_UTIL_MAX_PARTITIONS];

    /* Initialize array to default values, SIZE_MAX is used to mark invalid addresses */
    for (int i = 0; i < M32_FIRMWARE_UTIL_MAX_PARTITIONS; i++)
    {
      headerAddresses[i] = SIZE_MAX;
    }

    /* Search for all partitions in the image */
    size_t headerStartLength = strlen(device->RecoveryHeaderStart);
    for (size_t bufferIndex = 0; bufferIndex < (fileStatus->st_size - M32_FIRMWARE_UTIL_FW_HEADER_LENGTH); bufferIndex++)
    {
      if (memcmp(&(buffer[bufferIndex]), device->RecoveryHeaderStart, headerStartLength) == 0)
      {
        printf("Found partition header at address 0x%08lX\n", bufferIndex);
        headerAddresses[partitionCount] = bufferIndex;
        partitionCount++;

        if (partitionCount == M32_FIRMWARE_UTIL_MAX_PARTITIONS)
        {
          printf("Reached maximum of %i partitions, stopping search", partitionCount);
          break;
        }
      }
    }

    for (int partition = 0; partition < partitionCount; partition++)
    {
      size_t partitionStart; 
      size_t partitionLength;
      uint8_t* partitionData;

      partitionStart = headerAddresses[partition];
      partitionData = &(buffer[partitionStart]);

      if (((partition + 1) < M32_FIRMWARE_UTIL_MAX_PARTITIONS) &&
          (headerAddresses[partition + 1] != SIZE_MAX))
      {
        /* There is another valid partition afterwards, just calcualte the adress difference */
        partitionLength = headerAddresses[partition + 1] - headerAddresses[partition];
      }
      else
      {
        /* There are no further partitions, the current one must be the last one */
        partitionLength = fileStatus->st_size - headerAddresses[partition];
      }

      partitionLength -= M32_FIRMWARE_UTIL_FW_HEADER_LENGTH;

      size_t partitionLengthOld = partitionData[M32_FIRMWARE_UTIL_FW_DATA_LENGTH_OFFSET] | 
                                 (partitionData[M32_FIRMWARE_UTIL_FW_DATA_LENGTH_OFFSET + 1] << 8) | 
                                 (partitionData[M32_FIRMWARE_UTIL_FW_DATA_LENGTH_OFFSET + 2] << 16) | 
                                 (partitionData[M32_FIRMWARE_UTIL_FW_DATA_LENGTH_OFFSET + 3] << 24);

      if (partitionLengthOld != partitionLength)
      {
        printf("Updating data length in partition %i from %li (0x%08lX) to %li (0x%08lX)\n", 
        partition, partitionLengthOld, partitionLengthOld, partitionLength, partitionLength);
        partitionData[M32_FIRMWARE_UTIL_FW_DATA_LENGTH_OFFSET] = partitionLength & 0xFFu;
        partitionData[M32_FIRMWARE_UTIL_FW_DATA_LENGTH_OFFSET + 1] = (partitionLength >> 8) & 0xFFu; 
        partitionData[M32_FIRMWARE_UTIL_FW_DATA_LENGTH_OFFSET + 2] = (partitionLength >> 16) & 0xFFu;
        partitionData[M32_FIRMWARE_UTIL_FW_DATA_LENGTH_OFFSET + 3] = (partitionLength >> 24) & 0xFFu;
      }

      Caclulate16BitSum(
        "data",
        partition,
        &(partitionData[M32_FIRMWARE_UTIL_FW_HEADER_LENGTH]),
        partitionLength,
        &(partitionData[CHECKUM_PATCHER_DATA_CHECKSUM_OFFSET]),
        false);
      Caclulate16BitSum(
        "header",
        partition,
        partitionData,
        CHECKUM_PATCHER_HEADER_CHECKSUM_OFFSET,
        &(partitionData[CHECKUM_PATCHER_HEADER_CHECKSUM_OFFSET]), 
        true);
    }
    
    if (partitionCount == 0)
    {
      printf("No partitions found in input file");
    }
    else if (WriteBufferToFile(buffer, fileStatus->st_size, outputFile) != 0)
    {
      printf("Error during writing the updated recovery image to file %s\n", outputFile);
    }
    else
    {
      status = 0;
    }
  }

  if (buffer != NULL)
  {
    free(buffer);
    buffer = NULL;
  }

  return status;
}

static int CreateFactoryImageFromRecoveryImage(FILE* file, struct stat* fileStatus, const char* outputFile, const M32FirmwareUtilDeviceInfoType* device)
{
  int status = 1;
  uint8_t* factoryImage = NULL;

  size_t factoryImageSize = 0;

  const size_t recoveryImageSize = fileStatus->st_size;
  factoryImageSize += recoveryImageSize;
  
  /* 3 Headers are added, two for SHA512 verification, one for AES encryption */
  factoryImageSize += 3 * M32_FIRMWARE_HEADER_LENGTH;

  /* 2 signature are added, one for the decrypted image, one for the factory image */
  factoryImageSize += 2 * M32_FIRMWARE_SIGNATURE_LENGTH;

  /* Data for the decryption is added: IV and Salt */
  factoryImageSize += M32_FIRMWARE_DECRYPTION_INFO_LENGTH;

  /* Size of the encrypted image wihtout encryption header */
  const size_t encryptedImageWithoutHeaderSize = recoveryImageSize + M32_FIRMWARE_HEADER_LENGTH + M32_FIRMWARE_SIGNATURE_LENGTH;

  /* Size of the factory image wihtout SHA512 header and without signature */
  const size_t factoryImageWithoutHeaderSize = encryptedImageWithoutHeaderSize + M32_FIRMWARE_HEADER_LENGTH + M32_FIRMWARE_DECRYPTION_INFO_LENGTH;

  uint8_t IV[16] = { 0x99, 0x38, 0x0c, 0x25, 0xae, 0xcc, 0x79, 0xd3, 0x9b, 0x14, 0x5a, 0xc0, 0x43, 0x53, 0xbb, 0xe9 };

  /* Add AES_BLOCK_SIZE because encrypted data can be larger with AES CBC padding */
  if ((factoryImage = malloc(factoryImageSize + AES_BLOCK_SIZE)) == NULL)
  {
    printf("Unable to allocate buffer to create the factory image\n");
  }
  else
  {
    int encryptedDataLength = 0;
    uint8_t* factoryImageHeader = factoryImage;
    uint8_t* encryptionHeader = &(factoryImageHeader[M32_FIRMWARE_HEADER_LENGTH]);
    uint8_t* ecnryptionInfo = &(encryptionHeader[M32_FIRMWARE_HEADER_LENGTH]);
    uint8_t* saltHeader = &(ecnryptionInfo[M32_FIRMWARE_INITIALIZATION_VECTOR_LENGTH]);
    uint8_t* recoveryImageWithHeader = &(ecnryptionInfo[M32_FIRMWARE_DECRYPTION_INFO_LENGTH]);
    uint8_t* recoveryImage = &(recoveryImageWithHeader[M32_FIRMWARE_HEADER_LENGTH]);
    uint8_t* recoveryImageSignature = &(recoveryImage[recoveryImageSize]);
  
    if (fread(recoveryImage, 1, fileStatus->st_size, file) != fileStatus->st_size)
    {
      printf("Unable to read recovery image from input file\n");
    }
    else if (CreateSha512VerificatioinHeader(recoveryImageWithHeader, recoveryImageSize) != 0)
    {
      printf("Unable to create SHA512 verification header for recovery image\n");
    }
    else if (CreateSha512VerificatioinSignature(recoveryImage, recoveryImageSize, device) != 0)
    {
      printf("Unable to create SHA512 verification signature for recovery image\n");
    }
    else if (WriteDebugBufferToFile(recoveryImageSignature, M32_FIRMWARE_SIGNATURE_LENGTH, "Sig1.bin") != 0)
    {
      printf("Error during writing debug output file %s\n", "Sig1.bin");
    }
    else if (WriteDebugBufferToFile(recoveryImageWithHeader, recoveryImageSize + M32_FIRMWARE_HEADER_LENGTH + M32_FIRMWARE_SIGNATURE_LENGTH, "FW_and_Sig1.bin") != 0)
    {
      printf("Error during writing debug output file %s\n", "FW_and_Sig1.bin");
    }
    else if (EncryptAes128Cbc(recoveryImageWithHeader, 
                              encryptedImageWithoutHeaderSize, 
                              recoveryImageWithHeader,
                              saltHeader,
                              device->FirmwareKey, 
                              IV,
                              &encryptedDataLength) != 0)
    {
      printf("Unable to encrypt image\n");
    }
    else if (WriteDebugBufferToFile(saltHeader, encryptedDataLength + M32_FIRMWARE_SALT_INFO_LENGTH, "FWenc.bin") != 0)
    {
      printf("Error during writing debug output file %s\n", "FWenc.bin");
    }
    else if (CreateAes128CbcEncryptionHeader(encryptionHeader, encryptedDataLength + M32_FIRMWARE_SALT_INFO_LENGTH) != 0)
    {
      printf("Unable to create AES128 CBC header\n");
    }
    else if (WriteAes128CbcIvToBuffer(ecnryptionInfo, IV, sizeof(IV)) != 0)
    {
      printf("Unable to write AES128 CBD IV\n");
    }
    else if (WriteDebugBufferToFile(ecnryptionInfo, M32_FIRMWARE_INITIALIZATION_VECTOR_LENGTH, "IV.bin") != 0)
    {
      printf("Error during writing debug output file %s\n", "FWenc.bin");
    }
    else if (CreateSha512VerificatioinHeader(factoryImageHeader, encryptedDataLength + M32_FIRMWARE_DECRYPTION_INFO_LENGTH + M32_FIRMWARE_HEADER_LENGTH) != 0)
    {
      printf("Unable to create SHA512 verification header for recovery image\n");
    }
    else if (CreateSha512VerificatioinSignature(encryptionHeader, encryptedDataLength + M32_FIRMWARE_DECRYPTION_INFO_LENGTH + M32_FIRMWARE_HEADER_LENGTH, device) != 0)
    {
      printf("Unable to create SHA512 verification signature for recovery image\n");
    }
    else if (WriteBufferToFile(factoryImage, encryptedDataLength + M32_FIRMWARE_DECRYPTION_INFO_LENGTH + 2* M32_FIRMWARE_HEADER_LENGTH + M32_FIRMWARE_SIGNATURE_LENGTH, outputFile) != 0)
    {
      printf("Error during writing the factory image to file %s\n", outputFile);
    }
    else
    {
      status = 0;
    }
  }

  if (factoryImage != NULL)
  {
    free(factoryImage);
    factoryImage = NULL;
  }
  return status;
}

/// @brief
///   Creates a AES128 CBD encryption header for the specific image size.
/// @param buffer
///   The buffer to which the verification header is written to.
/// @param imageSize
///   The size of the image for which the header is created.
/// @return
///   The function returns 0 if the creation of the header was successful; otherwise 1.
static int CreateAes128CbcEncryptionHeader(uint8_t* buffer, size_t imageSize)
{
  memcpy(buffer, M32FirmwareUtilHeaderStart, strlen(M32FirmwareUtilHeaderStart));

  /* Constant 0x21 0x00 0x00 0x00 */
  buffer[4] = 0x21;
  buffer[5] = 0x00;
  buffer[6] = 0x00;
  buffer[7] = 0x00;

  /* Length of the data to verify (little endian format) */
  buffer[8] = imageSize & 0xFF;
  buffer[9] = (imageSize >> 8) & 0xFF;
  buffer[10] = (imageSize >> 16) & 0xFF;
  buffer[11] = (imageSize >> 24) & 0xFF;

  /* Constant 0x2B 0x1A */
  buffer[12] = 0x2B;
  buffer[13] = 0x1A;

  buffer[14] = 0;
  buffer[15] = 0;

  for (uint8_t position = 0; position < 14; position++)
  {
    buffer[14] += buffer[position]; /* Byte sum of byte 0-13 */
    buffer[15] ^= buffer[position]; /* XOR of byte 0-13 */
  }

  return 0;
}

/// @brief
///   Creates a SHA512 verification header for the specific image size.
/// @param buffer
///   The buffer to which the verification header is written to.
/// @param imageSize
///   The size of the image for which the header is created.
/// @return
///   The function returns 0 if the creation of the header was successful; otherwise 1.
static int CreateSha512VerificatioinHeader(uint8_t* buffer, size_t imageSize)
{
  memcpy(buffer, M32FirmwareUtilHeaderStart, strlen(M32FirmwareUtilHeaderStart));

  /* Length of the data to verify (little endian format) */
  buffer[4] = imageSize & 0xFF;
  buffer[5] = (imageSize >> 8) & 0xFF;
  buffer[6] = (imageSize >> 16) & 0xFF;
  buffer[7] = (imageSize >> 24) & 0xFF;

  /* Constant 0x00 0x01 0x00 0x00 */
  buffer[8] = 0x00;
  buffer[9] = 0x01;
  buffer[10] = 0x00;
  buffer[11] = 0x00;


  /* Constant 0x2B 0x1A */
  buffer[12] = 0x2B;
  buffer[13] = 0x1A;

  buffer[14] = 0;
  buffer[15] = 0;

  for (uint8_t position = 0; position < 14; position++)
  {
    buffer[14] += buffer[position]; /* Byte sum of byte 0-13 */
    buffer[15] ^= buffer[position]; /* XOR of byte 0-13 */
  }

  return 0;
}

/// @brief
///   Creates a SHA512 verification signature and stores it at the end of the buffer.
/// @param buffer
///   The buffer containing the data for which the signature is created.
///   There must be 256 additional bytes at the end of the buffer to store the signature.
/// @param imageSize
///   The size of the image without the signature.
/// @param device
///   Pointer to device specific information.
/// @return
///   The function returns 0 if the creation of the signature was successful; otherwise 1.
static int CreateSha512VerificatioinSignature(uint8_t* buffer, size_t imageSize, const M32FirmwareUtilDeviceInfoType* device)
{
  int status = 1;
  BIO* bio = NULL;
  uint8_t digest[SHA512_DIGEST_LENGTH];
  SHA512_CTX sha512Context;
  RSA* rsaPrivateKey = NULL;
  EVP_PKEY* pkey = NULL;
  EVP_MD_CTX* mdctx = NULL;
  unsigned int signatureLength;

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  if (SHA512_Init(&sha512Context) != 1)
  {
    PrintOpenSSLError("SHA512_Init");
  }
  else if (SHA512_Update(&sha512Context, buffer, imageSize) != 1)
  {
    PrintOpenSSLError("SHA512_Update");
  }
  else if (SHA512_Final(digest, &sha512Context) != 1)
  {
    PrintOpenSSLError("SHA512_Final");
  }
  else if ((bio = BIO_new_mem_buf(device->PrivateKey, -1)) == NULL)
  {
    PrintOpenSSLError("BIO_new_mem_buf");
  }
  else if ((rsaPrivateKey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, (void*)device->Passphrase)) == NULL)
  {
    PrintOpenSSLError("PEM_read_bio_RSAPrivateKey");
  }
  else if ((pkey = EVP_PKEY_new()) == NULL)
  {
    PrintOpenSSLError("EVP_PKEY_new");
  }
  else if ((EVP_PKEY_assign_RSA(pkey, rsaPrivateKey)) != 1)
  {
    PrintOpenSSLError("EVP_PKEY_assign_RSA");
  }
  else if ((mdctx = EVP_MD_CTX_new()) == NULL)
  {
    PrintOpenSSLError("EVP_MD_CTX_new");
  }
  else if ((EVP_SignInit(mdctx, EVP_sha512())) != 1)
  {
    PrintOpenSSLError("EVP_SignInit");
  }
  else if ((EVP_SignUpdate(mdctx, digest, sizeof(digest))) != 1)
  {
    PrintOpenSSLError("EVP_SignUpdate");
  }
  else if ((EVP_SignFinal(mdctx, &(buffer[imageSize]), &signatureLength, pkey)) != 1)
  {
    PrintOpenSSLError("EVP_SignFinal");
  }
  else if (signatureLength != M32_FIRMWARE_SIGNATURE_LENGTH)
  {
    printf("Invalid signature length. Acutal: %u, expected: %u", signatureLength, M32_FIRMWARE_SIGNATURE_LENGTH);
  }
  else
  {
    status = 0;
  }

  if (bio != NULL)
  {
    BIO_free(bio);
    bio = NULL;
  }

  if (mdctx != NULL)
  {
    EVP_MD_CTX_free(mdctx);
    mdctx = NULL;
  }

  if (pkey != NULL)
  {
    EVP_PKEY_free(pkey);
    pkey = NULL;
  }

  EVP_cleanup();
  ERR_free_strings();
}

/// @brief
///   Decrypts and verifies a OEM firmware file to get the firmware image which can be used with TFTP.
/// @param file
///   The FILE handle of the input file.
/// @param fileStatus
///   The file status of the input file.
/// @param outputFile
///   The name of the output file.
/// @return
///   The function returns 0 if the decryption and verification was successful; otherwise 1.
static int DecryptFactoryImage(FILE* file, struct stat* fileStatus, const char* outputFile, const M32FirmwareUtilDeviceInfoType* device)
{
  int status = 1;
  uint8_t* fileBuffer = NULL;
  size_t currentBlockLength = 0;
  size_t currentBlockOffset = 0;

  uint8_t* decrpytedData = NULL;
  uint8_t ivHex[AES_BLOCK_SIZE];

  /* Offset 0x00: Header of OEM firmware */
  if ((fileBuffer = malloc(fileStatus->st_size)) == NULL)
  {
    printf("Unable to allocate buffer to read OEM firmware\n");
  }
  else if (fread(fileBuffer, 1, fileStatus->st_size, file) != fileStatus->st_size)
  {
    printf("Unable to read OEM firmware from input file\n");
  }
  else if (GetDataLengthFromVerificationHeader(&(fileBuffer[currentBlockOffset]), &currentBlockLength) != 0)
  {
    printf("Unable to get block length of OEM firmware\n");
  }
  /* Offset 0x10: Header for verification of IV and encrypted firmware */
  else if ((currentBlockOffset += M32_FIRMWARE_HEADER_LENGTH) > fileStatus->st_size)
  {
    printf("Block offset for OEM firmware out of range\n");
  }
  else if (VerifySha512Signture(&(fileBuffer[currentBlockOffset]), currentBlockLength, device) != 0)
  {
    printf("Verification of IVandFWenc failed\n");
  }
  else if (GetDataLengthFromEncryptionHeader(&(fileBuffer[currentBlockOffset]), &currentBlockLength) != 0)
  {
    printf("Unable to get block length of IV and ecnrypted firmware\n");
  }
  /* Offset 0x20: IV and encrypted firmware */
  else if ((currentBlockOffset += M32_FIRMWARE_HEADER_LENGTH) > fileStatus->st_size)
  {
    printf("Block offset for IV and encrypted firmware out of range\n");
  }
  else if (ConvertAsciiIvToHexArray(&(fileBuffer[currentBlockOffset]), ivHex) != 0)
  {
    printf("Unable to convert ASCII IV to hexadecimal values\n");
  }
  /* Offset 0x31: Encrypted data */
  else if ((currentBlockOffset += M32_FIRMWARE_INITIALIZATION_VECTOR_LENGTH) > fileStatus->st_size)
  {
    printf("Block offset for encrypted firmware out of range\n");
  }
  else if ((decrpytedData = malloc(currentBlockLength)) == NULL)
  {
    printf("Unable to allocate buffer for decryption\n");
  }
  else if (DecryptAes128Cbc(&(fileBuffer[currentBlockOffset]), currentBlockLength, decrpytedData, device->FirmwareKey, ivHex) != 0)
  {
    printf("Decryption of firmware failed\n");
  }
  /* Still offset 0x31: but decrypted data */
  else if (GetDataLengthFromVerificationHeader(decrpytedData, &currentBlockLength) != 0)
  {
    printf("Unable to get block length of decrypted firmware\n");
  }
  else if ((currentBlockOffset += M32_FIRMWARE_HEADER_LENGTH) > fileStatus->st_size)
  {
    printf("Block offset for decrypted firmware out of range\n");
  }
  else if (VerifySha512Signture(decrpytedData + M32_FIRMWARE_HEADER_LENGTH, currentBlockLength, device) != 0)
  {
    printf("Verification of FWorig failed\n");
  }
  else if (WriteBufferToFile(decrpytedData + M32_FIRMWARE_HEADER_LENGTH, currentBlockLength, outputFile) != 0)
  {
    printf("Error during writing the recovery image to file %s\n", outputFile);
  }
  else
  {
    status = 0;
  }

  if (decrpytedData != NULL)
  {
    free(decrpytedData);
    decrpytedData = NULL;
  }

  if (fileBuffer != NULL)
  {
    free(fileBuffer);
    fileBuffer = NULL;
  }

  return status;
}


/// @brief
///   Performs SHA512 verification of a firmware image. The implementation represents the OpenSSL invocation
///   openssl dgst -sha512 -binary -out ${IV_AND_FIRMWARE_ENCRYPTED_DIGEST} ${IV_AND_FIRMWARE_ENCRYPTED}
///   openssl dgst -verify ${PUBLIC_KEY} -sha512 -binary -signature ${SIGNATURE_2} ${IV_AND_FIRMWARE_ENCRYPTED_DIGEST}
/// @param buffer
///   The buffer which contains the data to verify. The signature must be appended to the buffer.
/// @param bufferLength
///   The length of the buffer without signature.
/// @return
///   The function returns 0 if the verification was successful; otherwise 1.
static int VerifySha512Signture(const uint8_t* buffer, const size_t bufferLength, const M32FirmwareUtilDeviceInfoType* device)
{
  int status = 1;
  uint8_t digest[SHA512_DIGEST_LENGTH];
  SHA512_CTX sha512Context;
  BIO *bufio = NULL;
  EVP_PKEY* publicKey = NULL;

  EVP_MD_CTX* context;

  const uint8_t* signature = &(buffer[bufferLength]);
  
  if (SHA512_Init(&sha512Context) == 0)
  {
    PrintOpenSSLError("SHA512_Init");
  }
  else if (SHA512_Update(&sha512Context, buffer, bufferLength) == 0)
  {
    PrintOpenSSLError("SHA512_Update");
  }
  else if (SHA512_Final(digest, &sha512Context) == 0)
  {
    PrintOpenSSLError("SHA512_Final");
  }
  else if ((bufio = BIO_new_mem_buf(device->PublicKey, -1))  == 0)
  {
    PrintOpenSSLError("BIO_new_mem_buf");
  }
  else if ((publicKey = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL)) == NULL)
  {
    PrintOpenSSLError("PEM_read_bio_RSA_PUBKEY");
  }
  else if ((context = EVP_MD_CTX_new()) == NULL)
  {
    PrintOpenSSLError("EVP_MD_CTX_new");
  }
  else if ((EVP_DigestVerifyInit(context, NULL, EVP_sha512(), NULL, publicKey)) == 0)
  {
    PrintOpenSSLError("EVP_DigestVerifyInit");
  }
  else if (EVP_DigestVerifyUpdate(context, digest, SHA512_DIGEST_LENGTH) == 0)
  {
    PrintOpenSSLError("EVP_DigestVerifyUpdate");
  }
  else if (EVP_DigestVerifyFinal(context, signature, M32_FIRMWARE_SIGNATURE_LENGTH) == 0)
  {
    PrintOpenSSLError("EVP_DigestVerifyFinal");
  }
  else 
  {
    status = 0;
  }

  if (publicKey != NULL)
  {
    EVP_PKEY_free(publicKey);
    publicKey = NULL;
  }

  if (bufio != NULL)
  {
    BIO_free(bufio);
    bufio = NULL;
  }

  return status;
}

/// @brief 
///   Performs AES decryption of a firmware image. The implementation represents the OpenSSL invocation
///   openssl aes-128-cbc -d -md sha256 -in ${encryptedData} -out ${outputBuffer} -kfile {keyString} -iv {ivHex}
/// @param encryptedData
///   Buffer containing the encrypted data
/// @param encryptedLength
///   Length of the buffer in bytes containing the encrypted data
/// @param outputBuffer
///   Buffer for storing the decrypted data
/// @param keyString
///   The firmware key as string for decrypting the data
/// @param ivHex
///   The initialization vector as array of hex values
/// @return
///   The function returns 0 if decryption was successful; otherwise 1.
static int DecryptAes128Cbc(const uint8_t* encryptedData, size_t encryptedLength, uint8_t* outputBuffer, const char* keyString, const uint8_t* ivHex)
{
  int status = 1;
  EVP_CIPHER_CTX* ctx = NULL;
  int decryptedLength = 0;

  uint8_t iv[EVP_MAX_IV_LENGTH], key[EVP_MAX_KEY_LENGTH];
  EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), &(encryptedData[8]), keyString, strlen(keyString), 1, key, iv);

  // The first 8 bytes contain the string "Salted__" and the salt, the are not used for decryption
  encryptedData += 16;
  encryptedLength -= 16;

  if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
  {
    PrintOpenSSLError("EVP_CIPHER_CTX_new");
  }
  else if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, ivHex) == 0)
  {
    PrintOpenSSLError("EVP_DecryptInit_ex");
  }
  else if (EVP_DecryptUpdate(ctx, outputBuffer, &decryptedLength, encryptedData, encryptedLength) != 1)
  {
    PrintOpenSSLError("EVP_DecryptUpdate");
  }
  else if (EVP_DecryptFinal_ex(ctx, outputBuffer + decryptedLength, &decryptedLength) != 1)
  {
    PrintOpenSSLError("EVP_DecryptFinal_ex");
  }
  else
  {
    status = 0;
  }

  if (ctx != NULL)
  {
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
  }

  return status;
}


/// @brief
///   Performs AES encryption of a firmware image. The implementation represents the OpenSSL invocation
///   openssl aes-128-cbc -e -md sha256 -in {plainData} -out {outputBuffer} -kfile {keyString} -iv {ivHex}
/// @param plainData
///   Buffer containing the plain data
/// @param plainDataLength
///   Length of the buffer in bytes containing the plain data
/// @param outputBuffer
///   Buffer for storing the encrypted data
/// @param saltBuffer
///   Buffer for storing the salt data
/// @param keyString
///   The firmware key as string for encrypting the data
/// @param ivHex
///   The initialization vector as array of hex values
/// @param encryptedDataLength
///   Pointer to store the length of the encryted data. Because of AES CBC padding, the encrypted data can be longer than the input data.
/// @return 
static int EncryptAes128Cbc(const uint8_t* plainData, const size_t plainDataLength, uint8_t* outputBuffer, uint8_t* saltBuffer, const char* keyString, const uint8_t* ivHex, int* encryptedDataLength)
{
  int status = 1;
  EVP_CIPHER_CTX *ctx = NULL;
  int templength = 0;
  const uint8_t salt[8] = {0x65, 0xFC, 0x43, 0xBC, 0x67, 0xA3, 0x23, 0x35};

  /* Write "Salted__" and salt */
  memcpy(saltBuffer, "Salted__", 8);
  memcpy(saltBuffer + 8, salt, 8);
  
  *encryptedDataLength = 0;

  uint8_t iv[EVP_MAX_IV_LENGTH] = {0}, key[EVP_MAX_KEY_LENGTH] = {0};
  EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), salt, keyString, strlen(keyString), 1, key, iv);

  if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
  {
    PrintOpenSSLError("EVP_CIPHER_CTX_new");
  }
  else if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, ivHex) == 0)
  {
    PrintOpenSSLError("EVP_EncryptInit_ex");
  }
  else if (EVP_EncryptUpdate(ctx, outputBuffer, &templength, plainData, plainDataLength) != 1)
  {
    PrintOpenSSLError("EVP_EncryptUpdate");
  }
  else
  {
    *encryptedDataLength += templength;
    if (EVP_EncryptFinal_ex(ctx, outputBuffer + (*encryptedDataLength), &templength) != 1) 
    {
      PrintOpenSSLError("EVP_EncryptFinal_ex");
    }
    else
    {
      *encryptedDataLength += templength;
      status = 0;
    }
  }

  if (ctx != NULL)
  {
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
  }

  return status;
}

/// @brief
///   Reads the length of the data block (payload) from an header which is used for SHA512 verification.
///   The length of the block is stored in byte 4-7 in this case.
/// @param header
///   Pointer to the header data.
/// @param dataLength
///   Pointer to store the header length.
/// @return
///   The function returns 0 if reading of the header was successful; otherwise 1.
static int GetDataLengthFromVerificationHeader(uint8_t* header, size_t* dataLength)
{
  int status = 1;
  /* Header must begin with ASCII MH01 */
  if ((header[0] == 'M') && (header[1] == 'H') && (header[2] == '0') && (header[3] == '1'))
  {
    *dataLength = header[4] | (header[5] << 8) | (header[6] << 16) | (header[7] << 24);
    status = 0;
  }
  
  return status;
}

/// @brief
///   Reads the length of the data block (payload) from an header which is used for AES encryption.
///   The length of the block is stored in byte 8-11 in this case.
/// @param header
///   Pointer to the header data.
/// @param dataLength
///   Pointer to store the header length.
/// @return
///   The function returns 0 if reading of the header was successful; otherwise 1.
static int GetDataLengthFromEncryptionHeader(uint8_t* header, size_t* dataLength)
{
  int status = 1;
  /* Header must begin with ASCII MH01 */
  if ((header[0] == 'M') && (header[1] == 'H') && (header[2] == '0') && (header[3] == '1'))
  {
    *dataLength = header[8] | (header[9] << 8) | (header[10] << 16) | (header[11] << 24);
    status = 0;
  }
  
  return status;
}


/// @brief
///   Converts the ASCII IV for AES decryption which is stored in the firmware to hexadecimal values.
/// @param ivAscii
///   The ASCII IV string.
/// @param ivHex
///   The array in which the hex values are stored.
/// @return
///   The function returns 0 if converting of the IV was successful; otherwise 1.
static int ConvertAsciiIvToHexArray(const uint8_t ivAscii[AES_BLOCK_SIZE * 2], uint8_t ivHex[AES_BLOCK_SIZE])
{
  /* Convert ASCII IV to hex values */
  for (size_t i = 0; i < AES_BLOCK_SIZE; i++)
  {
    sscanf(&(ivAscii[i * 2]), "%2hhx", &(ivHex[i]));
  }

  return 0;
}

/// @brief
///   Writes data from a buffer to a file.
/// @param buffer
///   The buffer containing the data.
/// @param bufferSize
///   The lengths of the buffer.
/// @param outputFile
///   The path to the file to which the data will be written.
/// @return
///   The function returns 0 if writing was successful; otherwise 1.
static int WriteBufferToFile(const uint8_t* buffer, const size_t bufferSize, const char* outputFile)
{
  int status = 1;
  FILE* file = NULL;
  if ((file = fopen(outputFile, "wb")) == NULL)
  {
    printf("Unable to open file %s for writing\n", outputFile);
  }
  else if (fwrite(buffer, 1, bufferSize, file) != bufferSize)
  {
    printf("Error during writing to file %s\n", outputFile);
  }
  else
  {
    status = 0;
  }

  if (file != NULL)
  {
    fclose(file);
    file = NULL;
  }

  return status;
}

/// @brief
///   Writes data from a buffer to a file if debug output is enabled.
/// @param buffer
///   The buffer containing the data.
/// @param bufferSize
///   The lengths of the buffer.
/// @param outputFile
///   The path to the file to which the data will be written.
/// @return
///   The function returns 0 if writing was successful; otherwise 1.
static int WriteDebugBufferToFile(const uint8_t* buffer, const size_t bufferSize, const char* outputFile)
{
  int status = 1;
  if (M32FirmwareUtilWriteDebugFiles == true)
  {
    const char* pathSeparator = "/";
    const size_t outputFilePathLength = strlen(M32FirmwareUtilDebugTargetFolder) + strlen(pathSeparator) + strlen(outputFile) + 1;
    char* outputFilePath = malloc(outputFilePathLength);
    snprintf(outputFilePath, outputFilePathLength, "%s%s%s", M32FirmwareUtilDebugTargetFolder, pathSeparator, outputFile);
    
    status = WriteBufferToFile(buffer, bufferSize, outputFilePath);

    if (outputFilePath != NULL)
    {
      free(outputFilePath);
      outputFilePath = NULL;
    }
  }
  else
  {
    status = 0;
  }

  return status;
}

static int WriteAes128CbcIvToBuffer(uint8_t* buffer, const uint8_t* iv, const size_t ivLength)
{
  size_t i;
  for (i = 0; i < ivLength; i++)
  {
    sprintf(&(buffer[2 * i]), "%02x", iv[i]);
  }

  buffer[(2 * i)] = 0x0A;

  return 0;
}

/// @brief Prints errors messages of a failed OpenSSL API call.
/// @param api
///   The API which was called.
static void PrintOpenSSLError(const char* api)
{
  printf("%s failed\n", api);
  ERR_print_errors_fp(stdout);
}

static void Caclulate16BitSum(const char* name, uint32_t partitionIndex, uint8_t* buffer, size_t bufferLength, uint8_t* checksumBuffer, bool inverted)
{
  uint16_t checksumOld;
  uint16_t checksumNew;

  checksumOld = checksumBuffer[0] | (checksumBuffer[1] << 8);
  checksumNew = 0;
                              
  for (int i = 0; i < bufferLength; i+= 2)
  {
    unsigned short currentValue = buffer[i] | (buffer[i + 1] << 8);
    checksumNew += currentValue;
    
    /* Detect overflow */
    if (checksumNew < currentValue)
    {
      checksumNew++;
    }
  }

  if (inverted == true)
  {
    checksumNew = 0xFFFFu - checksumNew;
  }

  if (checksumNew != checksumOld)
  {
    printf("Updating %s checksum in partition %i from 0x%04X to 0x%04X\n", name, partitionIndex, checksumOld, checksumNew);
    checksumBuffer[0] = checksumNew & 0xFFu;
    checksumBuffer[1] = (checksumNew >> 8) & 0xFFu; 
  }
  else
  {
    printf("Keeping %s checksum in partition %i: 0x%04X\n", name, partitionIndex, checksumOld);
  }
}