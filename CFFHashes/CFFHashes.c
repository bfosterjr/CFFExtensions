#include <Windows.h>
#include <Windowsx.h>
#include <stdlib.h>
#include "CFFExplorerSDK.h"
#include "Extension.h"
#include "resource.h"
#include "Commctrl.h"

#include "hash.h"

#define MAX_LABEL_LEN   20
#define MAX_HASH_ITEMS  50
#define MAX_URL_LEN     128



typedef struct _HASH_ITEM
{
    BOOL    valid;
    CHAR    label[MAX_LABEL_LEN];
    PBYTE   addr;
    DWORD   size;
    FLOAT   entropy;
    CHAR    md5[MD5_HASH_LEN + 1];
    CHAR    sha1[SHA1_HASH_LEN + 1];
    CHAR    crc[CRC32_HASH_LEN + 1];
    CHAR    sha256[SHA256_HASH_LEN + 1];
}HASH_ITEM, *PHASH_ITEM;

PBYTE       g_object = NULL;
HASH_ITEM   g_hashItems[MAX_HASH_ITEMS];

HINSTANCE hInstance;
LRESULT CALLBACK DlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        hInstance = (HINSTANCE)hModule;
    }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}

UINT nCFFApiMask[] =
{
    m_eaGetObjectAddress,
    m_eaGetObjectSize,
    m_eaIsPE64,
    m_eaIsRvaValid,
    m_eaRvaToOffset,
    m_eaGetDataDirectory,
    (UINT)NULL
};

typedef struct _CFFAPI
{
    d_eaGetObjectAddress eaGetObjectAddress;
    d_eaGetObjectSize eaGetObjectSize;
    d_eaIsPE64 eaIsPE64;
    d_eaIsRvaValid eaIsRvaValid;
    d_eaRvaToOffset eaRvaToOffset;
    d_eaGetDataDirectory eaGetDataDirectory;

} CFFAPI, *PCFFAPI;

CFFAPI CFFApi;

static
void
_doHash
(
    DWORD index,
    CHAR* label,
    DWORD lebelLen,
    PVOID addr,
    DWORD length
)
{
    g_hashItems[index].valid = TRUE;
    strncpy_s((char*)&(g_hashItems[index].label), MAX_LABEL_LEN - 1, label, lebelLen);
    g_hashItems[index].addr = (PBYTE)addr;
    g_hashItems[index].size = length;
    md5_hash(g_hashItems[index].addr, g_hashItems[index].size, g_hashItems[index].md5);
    sha1_hash(g_hashItems[index].addr, g_hashItems[index].size, g_hashItems[index].sha1);
    crc32_hash(g_hashItems[index].addr, g_hashItems[index].size, g_hashItems[index].crc);
    sha256_hash(g_hashItems[index].addr, g_hashItems[index].size, g_hashItems[index].sha256);
}

static
void
_buildPEHashItems
(
DWORD index,
DWORD fileSize
)
{
    IMAGE_DOS_HEADER        *pDosHeader = (IMAGE_DOS_HEADER *)g_object;
    IMAGE_NT_HEADERS        *pNtHeaders = (IMAGE_NT_HEADERS *)(pDosHeader->e_lfanew + (ULONG_PTR)pDosHeader);
    PIMAGE_SECTION_HEADER   pSectionHdr = NULL;
    DWORD                   i           = 0;
    CHAR                    secName[MAX_LABEL_LEN];

    _doHash(index, "DOS Header", MAX_LABEL_LEN - 1, (PVOID)pDosHeader, sizeof(IMAGE_DOS_HEADER));
    index++;
    _doHash(index, "FileHeader", MAX_LABEL_LEN - 1, (PVOID)&(pNtHeaders->FileHeader), sizeof(IMAGE_FILE_HEADER));
    index++;
    _doHash(index, "Optional Header", MAX_LABEL_LEN - 1, (PVOID)&(pNtHeaders->OptionalHeader), pNtHeaders->FileHeader.SizeOfOptionalHeader);
    index++;

    pSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)&(pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    for (i = 0; i < pNtHeaders->FileHeader.NumberOfSections && index < MAX_HASH_ITEMS; i++)
    {
        ZeroMemory(secName, sizeof(secName));
        strncat_s(secName, MAX_LABEL_LEN, "Section: ", MAX_LABEL_LEN / 2);
        strncat_s(secName, MAX_LABEL_LEN, pSectionHdr->Name, 8);
        _doHash(index, secName, MAX_LABEL_LEN - 1 , g_object + pSectionHdr->PointerToRawData, pSectionHdr->SizeOfRawData);
        index++;
        pSectionHdr++;
    }
}

static
void
_buildHashItems(HWND hDlg)
{
    DWORD fileSize = 0;
    IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)g_object;
    
    __try
    {
        ZeroMemory(&g_hashItems, sizeof(g_hashItems));

        fileSize = (DWORD)CFFApi.eaGetObjectSize(hDlg);

        //Whole file
        _doHash(0, "File", MAX_LABEL_LEN - 1, g_object, (DWORD)CFFApi.eaGetObjectSize(hDlg));

        if (fileSize > (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)) &&
            pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
        {
            _buildPEHashItems(1, fileSize);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ZeroMemory(&g_hashItems, sizeof(g_hashItems));
    }

}


__declspec(dllexport) BOOL __cdecl ExtensionLoad(EXTINITDATA *pExtInitData)
{
    //
    // Retrieves API Interface
    //

    pExtInitData->RetrieveExtensionApi(nCFFApiMask, &CFFApi);

    return TRUE;
}

__declspec(dllexport) VOID __cdecl ExtensionUnload()
{
}

__declspec(dllexport) WCHAR * __cdecl ExtensionName()
{
    return L"Hashes";
}

__declspec(dllexport) WCHAR * __cdecl ExtensionDescription()
{
    return L"Provides CRC/MD5/SHA file and section (PE files) hashes";
}

EXTEVENTSDATA eed;

__declspec(dllexport) VOID *  __cdecl ExtensionExecute(LPARAM lParam)
{

    eed.cbSize = sizeof(EXTEVENTSDATA);
    eed.hInstance = hInstance;
    eed.DlgID = IDD_FORMVIEW;
    eed.DlgProc = DlgProc;

    return (VOID *)&eed;
}



LRESULT CALLBACK DlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    int     i           = 0;
    int     list_index  = 0;
    int     idata       = 0;
    char    offset[16];
    char    length[16];
    char    custom_md5[MD5_HASH_LEN + 1];
    char    custom_sha1[SHA1_HASH_LEN + 1];
    char    custom_crc[CRC32_HASH_LEN + 1];
    char    custom_sha256[SHA256_HASH_LEN + 1];
    int     offsetval   = 0;
    int     lengthval   = 0;
    char*   temp;
    char    url[MAX_URL_LEN];
    char    lang[4];

    switch (uMsg)
    {

        case WM_INITDIALOG:
        {
            if (g_object != CFFApi.eaGetObjectAddress(hDlg))
            {
                g_object = (PBYTE) CFFApi.eaGetObjectAddress(hDlg);
                _buildHashItems(hDlg);
            }
            
            for (i = 0; i < MAX_HASH_ITEMS; i++)
            {
                if (g_hashItems[i].valid)
                {
                    SendDlgItemMessageA(hDlg, IDC_LIST, LB_INSERTSTRING, i, (LPARAM)g_hashItems[i].label);
                }
                else
                {
                    break;
                }
            }

            
            break;
        }

        case WM_COMMAND:
        {
            switch (LOWORD(wParam))
            {
            case IDC_LIST:
            {
                if (LBN_SELCHANGE == HIWORD(wParam))
                {
                    SetDlgItemTextA(hDlg, IDC_MD5, "");
                    if (LB_ERR != (list_index = (int)SendDlgItemMessageA(hDlg, IDC_LIST, LB_GETCURSEL, 0, 0)))
                    {
                        SetDlgItemTextA(hDlg, IDC_MD5, g_hashItems[list_index].md5);
                        SetDlgItemTextA(hDlg, IDC_SHA1, g_hashItems[list_index].sha1);
                        SetDlgItemTextA(hDlg, IDC_CRC, g_hashItems[list_index].crc);
                        SetDlgItemTextA(hDlg, IDC_SHA256, g_hashItems[list_index].sha256);
                    }
                }
                break;
            }
            case IDC_HASH:
            {
                ZeroMemory(offset, sizeof(offset));
                ZeroMemory(length, sizeof(length));

                Edit_GetText(GetDlgItem(hDlg, IDC_OFFSET), offset, sizeof(offset) - 1);
                Edit_GetText(GetDlgItem(hDlg, IDC_LENGTH), length, sizeof(length) - 1);

                SetDlgItemTextA(hDlg, IDC_MD5, "error");
                SetDlgItemTextA(hDlg, IDC_SHA1, "error");
                SetDlgItemTextA(hDlg, IDC_CRC, "error");
                SetDlgItemTextA(hDlg, IDC_SHA256, "error");

                if (strlen(offset) > 0 && strlen(length) > 0)
                {
                    offsetval = strtol(offset, &temp, 16);
                    lengthval = strtol(length, &temp, 16);

                    if (offsetval >= 0 && offsetval < (int)CFFApi.eaGetObjectSize(hDlg) &&
                        lengthval > 0 && ((offsetval + lengthval) <= (int)CFFApi.eaGetObjectSize(hDlg)))
                    {
                        ZeroMemory(custom_md5, sizeof(custom_md5));
                        ZeroMemory(custom_sha1, sizeof(custom_sha1));
                        ZeroMemory(custom_crc, sizeof(custom_crc));
                        ZeroMemory(custom_sha256, sizeof(custom_sha256));

                        md5_hash(g_object + offsetval, lengthval, custom_md5);
                        sha1_hash(g_object + offsetval, lengthval, custom_sha1);
                        crc32_hash(g_object + offsetval, lengthval, custom_crc);
                        sha256_hash(g_object + offsetval, lengthval, custom_sha256);
                        SetDlgItemTextA(hDlg, IDC_MD5, custom_md5);
                        SetDlgItemTextA(hDlg, IDC_SHA1, custom_sha1);
                        SetDlgItemTextA(hDlg, IDC_CRC, custom_crc);
                        SetDlgItemTextA(hDlg, IDC_SHA256, custom_sha256);
                    }
                }

                break;
            }
            case IDC_BUTTONVT:
            {
                ZeroMemory(lang, sizeof(lang));
                if (0 == GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_SISO639LANGNAME,lang,4))
                {
                    ZeroMemory(lang, sizeof(lang));
                    strcat_s(lang, 3, "en");
                }

                ZeroMemory(url, sizeof(url));
                ZeroMemory(custom_sha256, sizeof(custom_sha256));

                Edit_GetText(GetDlgItem(hDlg, IDC_SHA256), custom_sha256, sizeof(custom_sha256));

                if (strlen(custom_sha256) > 10)
                {
                    strcat_s(url, MAX_URL_LEN, "https://www.virustotal.com/");
                    strcat_s(url, MAX_URL_LEN, lang);
                    strcat_s(url, MAX_URL_LEN, "/file/");
                    strcat_s(url, MAX_URL_LEN, custom_sha256);
                    strcat_s(url, MAX_URL_LEN, "/analysis/");

                    ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
                }
                break;
            }
            }
        }
    }
    return FALSE;
}