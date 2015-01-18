#include <windows.h>
#include <Wincrypt.h>

#include "hash.h"

#define MD5_LEN     16
#define SHA1_LEN    20
#define SHA256_LEN  32

CHAR g_rgbDigits[] = "0123456789abcdef";

BOOL
md5_hash
(
BYTE*   data,
DWORD   len,
CHAR    md5[MD5_HASH_LEN]
)
{
    BOOL    retVal = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[MD5_LEN];
    DWORD cbHash = MD5_LEN;
    DWORD i = 0;
    DWORD j = 0;

    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {

    }
    else if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {

    }
    else if (!CryptHashData(hHash, data, len, 0))
    {

    }
    else if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {

    }
    else if (MD5_LEN != cbHash)
    {

    }
    else
    {
        for (i = 0; i < cbHash; i++)
        {
            j = i * 2;
            md5[j] = g_rgbDigits[rgbHash[i] >> 4];
            md5[j + 1] = g_rgbDigits[rgbHash[i] & 0xf];
        }
        retVal = TRUE;
    }

    if (0 != hHash)
    {
        CryptDestroyHash(hHash);
    }
    if (0 != hProv)
    {
        CryptReleaseContext(hProv, 0);
    }

    return retVal;
}

BOOL
sha1_hash
(
BYTE*   data,
DWORD   len,
CHAR    sha1[SHA1_HASH_LEN]
)
{
    BOOL    retVal = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[SHA1_LEN];
    DWORD cbHash = SHA1_LEN;
    DWORD i = 0;
    DWORD j = 0;

    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {

    }
    else if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
    {

    }
    else if (!CryptHashData(hHash, data, len, 0))
    {

    }
    else if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {

    }
    else if (SHA1_LEN != cbHash)
    {

    }
    else
    {
        for (i = 0; i < cbHash; i++)
        {
            j = i * 2;
            sha1[j] = g_rgbDigits[rgbHash[i] >> 4];
            sha1[j + 1] = g_rgbDigits[rgbHash[i] & 0xf];
        }
        retVal = TRUE;
    }

    if (0 != hHash)
    {
        CryptDestroyHash(hHash);
    }
    if (0 != hProv)
    {
        CryptReleaseContext(hProv, 0);
    }

    return retVal;
}

BOOL
sha256_hash
(
BYTE*   data,
DWORD   len,
CHAR    sha256[SHA256_HASH_LEN]
)
{
    BOOL    retVal = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[SHA256_LEN];
    DWORD cbHash = SHA256_LEN;
    DWORD i = 0;
    DWORD j = 0;

    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_AES,
        CRYPT_VERIFYCONTEXT))
    {

    }
    else if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {

    }
    else if (!CryptHashData(hHash, data, len, 0))
    {

    }
    else if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {

    }
    else if (SHA256_LEN != cbHash)
    {

    }
    else
    {
        for (i = 0; i < cbHash; i++)
        {
            j = i * 2;
            sha256[j] = g_rgbDigits[rgbHash[i] >> 4];
            sha256[j + 1] = g_rgbDigits[rgbHash[i] & 0xf];
        }
        retVal = TRUE;
    }

    if (0 != hHash)
    {
        CryptDestroyHash(hHash);
    }
    if (0 != hProv)
    {
        CryptReleaseContext(hProv, 0);
    }

    return retVal;
}


/*
    rc_crc32() function from:

        http://rosettacode.org/wiki/CRC-32#C

    Used under GNU Free Documentation License 1.2

        http://www.gnu.org/licenses/fdl-1.2.html

*/
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static
uint32_t
rc_crc32(uint32_t crc, const char *buf, size_t len)
{
    static uint32_t table[256];
    static int have_table = 0;
    uint32_t rem;
    uint8_t octet;
    int i, j;
    const char *p, *q;

    /* This check is not thread safe; there is no mutex. */
    if (have_table == 0) {
        /* Calculate CRC table. */
        for (i = 0; i < 256; i++) {
            rem = i;  /* remainder from polynomial division */
            for (j = 0; j < 8; j++) {
                if (rem & 1) {
                    rem >>= 1;
                    rem ^= 0xedb88320;
                }
                else
                    rem >>= 1;
            }
            table[i] = rem;
        }
        have_table = 1;
    }

    crc = ~crc;
    q = buf + len;
    for (p = buf; p < q; p++) {
        octet = *p;  /* Cast to unsigned octet. */
        crc = (crc >> 8) ^ table[(crc & 0xff) ^ octet];
    }
    return ~crc;
}

BOOL
crc32_hash
(
BYTE*   data,
DWORD   len,
CHAR    crc32[CRC32_HASH_LEN]
)
{
    uint32_t    crc     = 0;
    PBYTE       rgbHash = (PBYTE)&crc;
    DWORD       i       = 0;
    DWORD       j       = 0;

    crc = rc_crc32(0, data, len);

    for ( i = 0; i < sizeof(crc); i++)
    {
        j = i * 2;
        crc32[j] = g_rgbDigits[rgbHash[i] >> 4];
        crc32[j + 1] = g_rgbDigits[rgbHash[i] & 0xf];
    }
    return TRUE;
}