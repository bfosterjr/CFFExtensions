#include <Windows.h>
#include <Windowsx.h>
#include <stdlib.h>
#include <stdio.h>
#include "CFFExplorerSDK.h"
#include "Extension.h"
#include "resource.h"
#include "Commctrl.h"

#include "string.h"


#define MAX_STRING_LEN      0x1000
#define MIN_STRING_LEN      3
#define PIXELS_PER_CHAR     6

PBYTE       g_object        = NULL;
BOOL        g_stringsdone   = FALSE;
//int         g_lastlen       = 0;
BOOL        g_prevwide   = FALSE;
HANDLE      g_thread        = NULL;
HANDLE      g_event         = NULL;
PVOID       g_lastObj       = NULL;
BOOL        g_showOffsets   = FALSE;
BOOL        g_prevascii     = FALSE;

HINSTANCE hInstance;
LRESULT CALLBACK DlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

typedef struct _THREAD_ARGS
{
    HWND    hDlg;
    int     minLen;
    BOOL    wide;
    BOOL    ascii;
    BOOL    offsets;
}THREAD_ARGS, *PTHREAD_ARGS;


BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        hInstance = (HINSTANCE)hModule;

        g_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        if (NULL != g_thread)
        {
            TerminateThread(g_thread, 0);
            CloseHandle(g_thread);
        }
        CloseHandle(g_event);
        break;
    }

    return TRUE;
}

UINT nCFFApiMask[] =
{
    m_eaGetObjectAddress,
    m_eaGetObjectSize,
    (UINT)NULL
};

typedef struct _CFFAPI
{
    d_eaGetObjectAddress eaGetObjectAddress;
    d_eaGetObjectSize eaGetObjectSize;
} CFFAPI, *PCFFAPI;

CFFAPI CFFApi;


__declspec(dllexport) BOOL __cdecl ExtensionLoad(EXTINITDATA *pExtInitData)
{

    pExtInitData->RetrieveExtensionApi(nCFFApiMask, &CFFApi);

    return TRUE;
}

__declspec(dllexport) VOID __cdecl ExtensionUnload()
{
}

__declspec(dllexport) WCHAR * __cdecl ExtensionName()
{
    return L"Strings";
}

__declspec(dllexport) WCHAR * __cdecl ExtensionDescription()
{
    return L"Finds strings within the given file";
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

static
void
_saveListView
(
    PCHAR   filepath,
    HWND    hDlg
)
{
    HANDLE  hFile               = INVALID_HANDLE_VALUE;
    int     listCount           = 0;
    int     i                   = 0;
    CHAR    string[MAX_STRING_LEN];
    int     len                 = 0;
    DWORD   bytesWritten        = 0;
    PCHAR   lineFeed            = "\r\n";
    BOOL    type                = (g_prevascii && g_prevwide);
    BOOL    offset              = g_showOffsets;
    BOOL    headers             = type || offset;
    LVITEM  lvi                 = { 0 };
    CHAR    typeStr[2]          = { 0 };
    CHAR    offsetStr[10]       = { 0 };

    __try
    {
        hFile = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE,
            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (INVALID_HANDLE_VALUE != hFile)
        {
            if (headers)
            {
                if (type)
                {
                    WriteFile(hFile, "Type,", sizeof("Type,") - 1, &bytesWritten, NULL);
                }
                if (offset)
                {
                    WriteFile(hFile, "Offset,", sizeof("Offset,") - 1, &bytesWritten, NULL);
                }
                WriteFile(hFile, "String", sizeof("String") - 1, &bytesWritten, NULL);
                WriteFile(hFile, lineFeed, 2, &bytesWritten, NULL);
            }

            if (0 < (listCount = (int)ListView_GetItemCount(GetDlgItem(hDlg, IDC_STRINGLIST))) )
            {
                for (i = 0; i < listCount; i++)
                {
                    if (headers)
                    {
                        if (type)
                        {
                            ZeroMemory(typeStr, sizeof(typeStr));
                            lvi.mask = LVIF_TEXT;
                            lvi.iItem = i;
                            lvi.iSubItem = 0;
                            lvi.cchTextMax = sizeof(typeStr);
                            lvi.pszText = typeStr;
                            if (0 < (len = (int)SendDlgItemMessageA(hDlg, IDC_STRINGLIST, LVM_GETITEMTEXT, i, (LPARAM)&lvi)))
                            {
                                WriteFile(hFile, lvi.pszText, len, &bytesWritten, NULL);
                                WriteFile(hFile, "," , 1, &bytesWritten, NULL);
                            }
                        }

                        if (offset)
                        {
                            ZeroMemory(offsetStr, sizeof(offsetStr));
                            lvi.mask = LVIF_TEXT;
                            lvi.iItem = i;
                            lvi.iSubItem = type;
                            lvi.cchTextMax = sizeof(offsetStr);
                            lvi.pszText = offsetStr;
                            if (0 < (len = (int)SendDlgItemMessageA(hDlg, IDC_STRINGLIST, LVM_GETITEMTEXT, i, (LPARAM)&lvi)))
                            {
                                WriteFile(hFile, lvi.pszText, len, &bytesWritten, NULL);
                                WriteFile(hFile, ",", 1, &bytesWritten, NULL);
                            }
                        }
                    }

                    ZeroMemory(string, sizeof(string));

                    lvi.mask = LVIF_TEXT;
                    lvi.iItem = i;
                    lvi.iSubItem = offset + type;
                    lvi.cchTextMax = sizeof(string);
                    lvi.pszText = string;
                    if (0 < (len = (int)SendDlgItemMessageA(hDlg, IDC_STRINGLIST, LVM_GETITEMTEXT, i, (LPARAM)&lvi)))
                    {
                        WriteFile(hFile, lvi.pszText, len, &bytesWritten, NULL);
                        WriteFile(hFile, lineFeed, 2, &bytesWritten, NULL);
                    }

                }
            }
        }
    }
    __finally
    {
        if (INVALID_HANDLE_VALUE != hFile)
        {
            CloseHandle(hFile);
        }
    }

}
static
void
_setViewColums
(
HWND hDlg,
BOOL offset,
BOOL type
)
{
    LV_COLUMNA lvc = { 0 };

    ListView_SetExtendedListViewStyle(GetDlgItem(hDlg, IDC_STRINGLIST), LVS_EX_FULLROWSELECT);

    ZeroMemory(&lvc, sizeof(lvc));

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = "String";
    lvc.cx = PIXELS_PER_CHAR * sizeof("String");

    ListView_InsertColumn(GetDlgItem(hDlg, IDC_STRINGLIST), 0, &lvc);
    ListView_SetColumnWidth(GetDlgItem(hDlg, IDC_STRINGLIST), 0, LVSCW_AUTOSIZE_USEHEADER);

    if (offset)
    {
        lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
        lvc.fmt = LVCFMT_LEFT;
        lvc.pszText = "    Offset    ";
        lvc.cx = PIXELS_PER_CHAR * sizeof("    Offset    ");
        ListView_InsertColumn(GetDlgItem(hDlg, IDC_STRINGLIST), 0, &lvc);
        ListView_SetColumnWidth(GetDlgItem(hDlg, IDC_STRINGLIST), 0, LVSCW_AUTOSIZE_USEHEADER);
    }

    if (type)
    {
        lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
        lvc.fmt = LVCFMT_LEFT;
        lvc.pszText = "Type";
        lvc.cx = PIXELS_PER_CHAR * sizeof("Type");
        ListView_InsertColumn(GetDlgItem(hDlg, IDC_STRINGLIST), 0, &lvc);
        ListView_SetColumnWidth(GetDlgItem(hDlg, IDC_STRINGLIST), 0, LVSCW_AUTOSIZE_USEHEADER);
    }

}

static
void
_insertString
(
    HWND hDlg,
    PCHAR string,
    int stringlen,
    BOOL showOffset,
    int offset,
    BOOL showType,
    BOOL wide,
    int index
)
{
    LV_ITEMA lvi            = { 0 };
    CHAR    stroffset[10]   = { 0 };
    int     subitem         = 0;

    ZeroMemory(&lvi, sizeof(lvi));

    if (showType)
    {
        lvi.mask = LVIF_TEXT;
        lvi.pszText = wide ? "W" : "A";
        lvi.cchTextMax = 2;
        lvi.iItem = index;
        lvi.iSubItem = subitem;
        SendDlgItemMessageA(hDlg, IDC_STRINGLIST, subitem == 0 ? LVM_INSERTITEMA : LVM_SETITEMA, 0, (LPARAM)&lvi);
        subitem++;
    }

    if (showOffset)
    {
        ZeroMemory(stroffset, sizeof(stroffset));
        _snprintf_s(stroffset, sizeof(stroffset), sizeof(stroffset), "%08X", offset);

        lvi.mask = LVIF_TEXT;
        lvi.pszText = stroffset;
        lvi.cchTextMax = sizeof(stroffset);
        lvi.iItem = index;
        lvi.iSubItem = subitem;
        SendDlgItemMessageA(hDlg, IDC_STRINGLIST, subitem == 0 ? LVM_INSERTITEMA : LVM_SETITEMA, 0, (LPARAM)&lvi);
        subitem++;
    }

    lvi.mask = LVIF_TEXT;
    lvi.pszText = string;
    lvi.cchTextMax = stringlen;
    lvi.iItem = index;
    lvi.iSubItem = subitem;
    SendDlgItemMessageA(hDlg, IDC_STRINGLIST, subitem == 0 ? LVM_INSERTITEMA : LVM_SETITEMA, 0, (LPARAM)&lvi);

}

static
void
_resetStringList
(
HWND hDlg
)
{
    ListView_DeleteAllItems(GetDlgItem(hDlg, IDC_STRINGLIST));
    while (ListView_DeleteColumn(GetDlgItem(hDlg, IDC_STRINGLIST), 0));
}


static
BOOL
_findStrings
(
    HWND    hDlg,
    DWORD   minLength,
    BOOL    ascii,
    BOOL    wide,
    BOOL    showOffset,
    BOOL    searchBoth
)
{

    PBYTE   fileptr     = g_object;
    PBYTE   fileend     = g_object;
    DWORD   filelen     = 0;
    CHAR    str[MAX_STRING_LEN] = { 0 };
    CHAR    strsfound[30] = { 0 };
    int     strlen      = 0;
    int     offset      = 0;
    int     index       = 0;
    DWORD   steplen     = 0;
    int     stepOffset  = 0;
    char    iswide   = 0;
    int     longestStr  = 0;
    BOOL    stop        = FALSE;
    BOOL    err         = FALSE;

    if (minLength < MIN_STRING_LEN)
    {
        minLength = MIN_STRING_LEN;
    }

    ResetEvent(g_event);

    filelen = CFFApi.eaGetObjectSize(hDlg);
    fileend += filelen;
    steplen = filelen / 100;

    if (searchBoth)
    {
        steplen *= 2;
    }


    while (fileptr + offset < fileend && !stop)
    {
        ZeroMemory(str, sizeof(str));
        strlen = string(fileptr, filelen, offset, wide, str, sizeof(str) - 1, &iswide);
            
        if (strlen >= (int)minLength)
        {
            if (index < MAXINT16)
            {
                if (strlen > longestStr)
                {
                    longestStr = strlen;
                }

                if ((ascii && !iswide) || (wide && iswide))
                {
                    _insertString(hDlg, str, strlen + 1, showOffset, offset, searchBoth, iswide, index);
                    index++;
                }
            }
            else
            {
                Edit_SetText(GetDlgItem(hDlg, IDC_STATUS), "ERROR: Exceeded string display limit (~32K strings). Increase min string length.");
                err = TRUE;
                break;
            }
        }

        offset += (strlen == 0) ? 1 : (iswide ? strlen * 2 : strlen);

        if (offset - stepOffset > (int)steplen)
        {
            SendDlgItemMessageA(hDlg, IDC_PROGRESS, PBM_STEPIT, 0, (LPARAM)0);
            stepOffset = offset;
        }
        if (WAIT_OBJECT_0 == WaitForSingleObject(g_event, 0))
        {
            stop = TRUE;
        }
    }
    ListView_SetColumnWidth(GetDlgItem(hDlg, IDC_STRINGLIST), showOffset + searchBoth, longestStr * PIXELS_PER_CHAR);

    if (!stop)
    {
        if (!err)
        {
            ZeroMemory(strsfound, sizeof(strsfound));
            _snprintf_s(strsfound, sizeof(strsfound), sizeof(strsfound), "Found %d strings.", index);
            Edit_SetText(GetDlgItem(hDlg, IDC_STATUS), strsfound);
        }
    }

    return stop || err;
}


DWORD
WINAPI
_findStringThreadFunc
(
    PVOID arg
)
{
    PTHREAD_ARGS    findStringsArg  = (PTHREAD_ARGS)arg;
    HWND            hDlg            = NULL;
    BOOL            stop            = FALSE;
    __try
    {
        hDlg = findStringsArg->hDlg;
        Edit_SetText(GetDlgItem(hDlg, IDC_STATUS), "");
        _resetStringList(hDlg);
        _setViewColums(hDlg, findStringsArg->offsets, 
                        findStringsArg->ascii && findStringsArg->wide);
        SendDlgItemMessageA(hDlg, IDC_PROGRESS, PBM_SETPOS, 0, (LPARAM)0);
        g_stringsdone = FALSE;
        g_prevascii = FALSE;
        g_prevwide = FALSE;
        g_lastObj = g_object;
        g_showOffsets = findStringsArg->offsets;
        if (!stop && findStringsArg->ascii)
        {
            stop = _findStrings(findStringsArg->hDlg, findStringsArg->minLen,
                findStringsArg->ascii, 0,
                findStringsArg->offsets, findStringsArg->wide && findStringsArg->ascii);
            g_prevascii = TRUE;
        }
        if (!stop && findStringsArg->wide)
        {
            stop = _findStrings(findStringsArg->hDlg, findStringsArg->minLen,
                0, findStringsArg->wide,
                findStringsArg->offsets, findStringsArg->wide && findStringsArg->ascii);
            g_prevwide = TRUE;
        }
        g_stringsdone = TRUE;
        SendDlgItemMessageA(hDlg, IDC_PROGRESS, PBM_SETPOS, 100, (LPARAM)0);
    }
    __finally
    {
        free(findStringsArg);
        CloseHandle(g_thread);
        g_thread = NULL;
    }
    return 0;
}



LRESULT CALLBACK DlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    int             i = 0;
    char            saveFilePath[MAX_PATH];
    char            minLenStr[10];
    OPENFILENAMEA   saveFile;
    DWORD           threadId = 0;
    PTHREAD_ARGS    findStringsArg = NULL;

    switch (uMsg)
    {

    case WM_INITDIALOG:
    {
        _setViewColums(hDlg,FALSE,FALSE);
        SendDlgItemMessageA(hDlg, IDC_PROGRESS, PBM_SETSTEP, 1, (LPARAM)0);
        CheckDlgButton(hDlg, IDC_ASCII, BST_CHECKED);
        g_object = (PBYTE)CFFApi.eaGetObjectAddress(hDlg);
        g_stringsdone = FALSE;
        g_prevwide = FALSE;
        break;
    }
    case WM_DESTROY:
    {
        SetEvent(g_event);
        break;
    }
    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDC_SAVE:
        {
            if (g_stringsdone)
            {
                ZeroMemory(saveFilePath, sizeof(saveFilePath));
                ZeroMemory(&saveFile, sizeof(saveFile));
                saveFile.lStructSize = sizeof(OPENFILENAMEA);
                saveFile.lpstrFile = saveFilePath;
                saveFile.nMaxFile = sizeof(saveFilePath);
                saveFile.lpstrDefExt = ".txt";
                saveFile.lpstrFilter = "Text File (.txt)\0*.txt\0\0";
                saveFile.Flags = OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY | OFN_CREATEPROMPT;
                if (GetSaveFileNameA(&saveFile))
                {
                    _saveListView(saveFilePath, hDlg);
                }
            }
            break;
        }
        case IDC_FINDSTRINGS:
        {

            if (NULL == g_thread)
            {
                if (NULL != (findStringsArg = calloc(sizeof(*findStringsArg),1)))
                {
                    ZeroMemory(minLenStr, sizeof(minLenStr));
                    Edit_GetText(GetDlgItem(hDlg, IDC_MINLEN), minLenStr, sizeof(minLenStr) - 1);

                    if (0 == strlen(minLenStr))
                    {
                        findStringsArg->minLen = 0;
                    }
                    else
                    {
                        findStringsArg->minLen = atoi(minLenStr);
                    }

                    if (IsDlgButtonChecked(hDlg, IDC_WIDE) == BST_CHECKED)
                    {
                        findStringsArg->wide = TRUE;
                    }

                    if (IsDlgButtonChecked(hDlg, IDC_OFFSETS) == BST_CHECKED)
                    {
                        findStringsArg->offsets = TRUE;
                    }

                    if (IsDlgButtonChecked(hDlg, IDC_ASCII) == BST_CHECKED)
                    {
                        findStringsArg->ascii = TRUE;
                    }

                    findStringsArg->hDlg = hDlg;

                    if (NULL == (g_thread = CreateThread(NULL, 0, _findStringThreadFunc, findStringsArg, 0, &threadId)))
                    {
                        free(findStringsArg);
                    }
                }
            }
        }
        }
    }
    }
    return FALSE;
}