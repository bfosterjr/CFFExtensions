
#include <Windows.h>


#define MD5_HASH_LEN    32
#define SHA1_HASH_LEN   40
#define SHA256_HASH_LEN 64
#define CRC32_HASH_LEN  8

BOOL
md5_hash
(
    BYTE*   data,
    DWORD   len,
    CHAR    md5[MD5_HASH_LEN]
);

BOOL
sha1_hash
(
    BYTE*   data,
    DWORD   len,
    CHAR    sha1[SHA1_HASH_LEN]
);

BOOL
sha256_hash
(
BYTE*   data,
DWORD   len,
CHAR    sha256[SHA256_HASH_LEN]
);


BOOL
crc32_hash
(
    BYTE*   data,
    DWORD   len,
    CHAR    crc32[CRC32_HASH_LEN]
);