#include <Windows.h>
#include <Windowsx.h>
#include <stdlib.h>
#include "CFFExplorerSDK.h"
#include "Extension.h"
#include "resource.h"
#include "Commctrl.h"

#include "yara.h"

#define MAX_FILE_SIZE   100000  //1MB

HINSTANCE hInstance;
LRESULT CALLBACK DlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

typedef struct _YARA_OPTIONS
{
    HWND hDlg;
    BOOL fastScan;
    BOOL showNamespace;
    BOOL nonMatch;
    BOOL moduleLoad;
    BOOL offsets;
    UINT maxMatches;
    UINT matchCount;
}YARA_OPTIONS, *PYARA_OPTIONS;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        hInstance = (HINSTANCE)hModule;

        yr_initialize();
    }

    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        yr_finalize_thread();
        break;
    case DLL_PROCESS_DETACH:
        yr_finalize();
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
    return L"Yara";
}

__declspec(dllexport) WCHAR * __cdecl ExtensionDescription()
{
    return L"Provides Yara scanning";
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
BOOL
_loadEditBox
(
    HWND    hDlg,
    UINT    editBoxID,
    PCHAR   defaultExt,
    PCHAR   filter
)
{
    HANDLE          hFile       = INVALID_HANDLE_VALUE;
    PVOID           text        = NULL;
    DWORD           len         = 0;
    DWORD           sizeHigh    = 0;
    DWORD           bytesRead   = 0;
    BOOL            retVal      = FALSE;
    OPENFILENAMEA   openFile;
    CHAR            openFilePath[MAX_PATH];

    ZeroMemory(openFilePath, sizeof(openFilePath));
    ZeroMemory(&openFile, sizeof(openFile));
    openFile.lStructSize = sizeof(OPENFILENAMEA);
    openFile.lpstrFile = openFilePath;
    openFile.nMaxFile = sizeof(openFilePath);
    openFile.lpstrDefExt = defaultExt;
    openFile.lpstrFilter = filter;
    openFile.Flags = OFN_OVERWRITEPROMPT | OFN_CREATEPROMPT;



    __try
    {
        if (!GetOpenFileName(&openFile))
        {
        }
        else if (INVALID_HANDLE_VALUE == (hFile = CreateFileA(openFilePath, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)))
        {
        }
        else if (0 == (len = GetFileSize(hFile, &sizeHigh)) || len > MAX_FILE_SIZE)
        {

        }
        else if (NULL == (text = calloc(len, 1)))
        {
        }
        else if (!ReadFile(hFile, text, len, &bytesRead, NULL))
        {

        }
        else if (0 == Edit_SetText(GetDlgItem(hDlg, editBoxID), text))
        {

        }
        else
        {
            retVal = TRUE;
        }
    }
    __finally
    {
        if (INVALID_HANDLE_VALUE != hFile)
        {
            CloseHandle(hFile);
        }
        if (NULL != text)
        {
            free(text);
        }
    }
    return retVal;
}


static
BOOL
_saveToFile
(
    PCHAR   filePath,
    HWND    hDlg,
    UINT    editBoxID
)
{
    HANDLE          hFile           = INVALID_HANDLE_VALUE;
    PVOID           text            = NULL;
    int             len             = 0;
    DWORD           bytesWritten    = 0;
    BOOL            retVal          = FALSE;
    __try
    {
        if (0 == (len = Edit_GetTextLength(GetDlgItem(hDlg, editBoxID))))
        {

        }
        else if (NULL == (text = calloc(len + 1, 1)))
        {
        }
        else if (0 == (len = Edit_GetText(GetDlgItem(hDlg, editBoxID), text, len + 1)))
        {

        }
        else if (INVALID_HANDLE_VALUE == (hFile = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE,
            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)))
        {
        }
        else if (!WriteFile(hFile, text, len, &bytesWritten, NULL))
        {

        }
        else
        {
            retVal = TRUE;
        }
    }
    __finally
    {
        if (INVALID_HANDLE_VALUE != hFile)
        {
            CloseHandle(hFile);
        }
        if (NULL != text)
        {
            free(text);
        }
    }
    return retVal;
}

static
BOOL
_saveEditBox
(
    HWND    hDlg,
    UINT    editBoxID,
    PCHAR   defaultExt,
    PCHAR   filter
)
{

    OPENFILENAMEA   saveFile;
    CHAR            saveFilePath[MAX_PATH];

    ZeroMemory(saveFilePath, sizeof(saveFilePath));
    ZeroMemory(&saveFile, sizeof(saveFile));
    saveFile.lStructSize = sizeof(OPENFILENAMEA);
    saveFile.lpstrFile = saveFilePath;
    saveFile.nMaxFile = sizeof(saveFilePath);
    saveFile.lpstrDefExt = defaultExt;
    saveFile.lpstrFilter = filter;
    saveFile.Flags = OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY | OFN_CREATEPROMPT;

    if (GetSaveFileNameA(&saveFile))
    {
        return _saveToFile(saveFilePath, hDlg, editBoxID);
    }
    return FALSE;
}


static
void
_appendEditBox
(
    HWND hDlg,
    UINT editBoxID,
    PCHAR text
)
{ 
    int end = GetWindowTextLength(GetDlgItem(hDlg, editBoxID));
    SendDlgItemMessageA(hDlg, editBoxID, EM_SETSEL, (WPARAM)end, (LPARAM)end);
    SendDlgItemMessageA(hDlg, editBoxID, EM_REPLACESEL, (WPARAM)0, (LPARAM)text);
}

static
void
_compilerCB
(
    int error_level,
    const char* file_name,
    int line_number,
    const char* message,
    void* user_data
)
{
    CHAR    linenum[20] = { 0 };
    CHAR    line[100] = { 0 };

    _appendEditBox((HWND)user_data, IDC_RESULT, error_level == YARA_ERROR_LEVEL_ERROR ? "ERROR: " : "WARNING: ");
    _appendEditBox((HWND)user_data, IDC_RESULT, (PCHAR)message);
    _appendEditBox((HWND)user_data, IDC_RESULT, "\r\n");
    if (line_number > 0)
    {
        sprintf_s(linenum, sizeof(linenum), "\tLine %d : ", line_number);
        _appendEditBox((HWND)user_data, IDC_RESULT, linenum);
        if (0 != Edit_GetLine(GetDlgItem((HWND)user_data, IDC_RULES), line_number - 1, line, sizeof(line) - 1))
        {
            _appendEditBox((HWND)user_data, IDC_RESULT, line);
        }
    }

    _appendEditBox((HWND)user_data, IDC_RESULT, "\r\n");
}


static
void
_appendString
(
    HWND hDlg,
    CHAR* data,
    int length
)
{
    CHAR str[10] = { 0 };
    int i = 0;

    for (i = 0; i < length; i++)
    {
        if (data[i] >= 32 && data[i] <= 126)
        {
            _snprintf_s(str, sizeof(str), sizeof(str), "%c", data[i]);
        }
        else
        {
            _snprintf_s(str, sizeof(str), sizeof(str), "\\x%02x", data[i]);
        }
        _appendEditBox(hDlg, IDC_RESULT, str);
    }
}

static
void 
_appendHexString
(
    HWND hDlg,
    CHAR* data,
    int length
)
{
    CHAR    hexstr[10] = { 0 };
    int     i         = 0;
    int     val       = 0;

    for (i = 0; i < min(32, length); i++)
    {
        val = (int)data[i];
        _snprintf_s(hexstr, sizeof(hexstr), sizeof(hexstr), "%02X", val);
        _appendEditBox(hDlg, IDC_RESULT, hexstr);
    }

    if (i < length)
    {
        _appendEditBox(hDlg, IDC_RESULT, "...");
    }
}

static
void
_appendRuleToEditBox
(
    YR_RULE* rule,
    BOOL doesMatch,
    PYARA_OPTIONS yrOpts
)
{
    YR_STRING* string = NULL;
    YR_MATCH* match = NULL;
    CHAR offset[60];

    if (yrOpts->showNamespace)
    {
        _appendEditBox(yrOpts->hDlg, IDC_RESULT, (PCHAR)rule->ns->name);
        _appendEditBox(yrOpts->hDlg, IDC_RESULT, ":");
    }
    _appendEditBox(yrOpts->hDlg, IDC_RESULT, (PCHAR)rule->identifier);

    _appendEditBox(yrOpts->hDlg, IDC_RESULT, "\r\n");

    if (yrOpts->offsets && doesMatch)
    {
        yr_rule_strings_foreach(rule, string)
        {
            yr_string_matches_foreach(string, match)
            {
                ZeroMemory(offset, sizeof(offset));
                _snprintf_s(offset, sizeof(offset), sizeof(offset), "\tOffset: %08X , Identifier: ", match->offset);
                _appendEditBox(yrOpts->hDlg, IDC_RESULT, offset);
                _appendEditBox(yrOpts->hDlg, IDC_RESULT, string->identifier);
                _appendEditBox(yrOpts->hDlg, IDC_RESULT, " , String: ");

                if (STRING_IS_HEX(string))
                {
                    _appendHexString(yrOpts->hDlg, match->data, match->length);
                }
                else
                {
                    _appendString(yrOpts->hDlg, match->data, match->length);
                }

                _appendEditBox(yrOpts->hDlg, IDC_RESULT, "\r\n");
            }
        }
    }

}

static
int 
_scanCB
(
    int message,
    void* message_data,
    void* user_data
)
{
    YR_RULE* rule = (YR_RULE*)message_data;
    YR_MODULE_IMPORT* yrMod = (YR_MODULE_IMPORT*)message_data;
    PYARA_OPTIONS yrOpts = (PYARA_OPTIONS)user_data;

    switch(message)
    {
    case CALLBACK_MSG_RULE_MATCHING:
    {
        yrOpts->matchCount++;
        _appendEditBox(yrOpts->hDlg, IDC_RESULT, "Match: ");
        _appendRuleToEditBox(rule, TRUE, yrOpts);
        break;
    }
    case CALLBACK_MSG_RULE_NOT_MATCHING:
    {
        if (yrOpts->nonMatch)
        {
            _appendEditBox(yrOpts->hDlg, IDC_RESULT, "Non-Match: ");
            _appendRuleToEditBox(rule, FALSE, yrOpts);
        }
        break;
    }
    case CALLBACK_MSG_IMPORT_MODULE:
    {
        if (yrOpts->moduleLoad)
        {
            _appendEditBox(yrOpts->hDlg, IDC_RESULT, "Module Import: ");
            _appendEditBox(yrOpts->hDlg, IDC_RESULT, (PCHAR) yrMod->module_name);
            _appendEditBox(yrOpts->hDlg, IDC_RESULT, "\r\n");
        }
        break;
    }
    default:
        break;
    }

    if (yrOpts->maxMatches > 0 &&
        yrOpts->matchCount >= yrOpts->maxMatches)
    {
        return CALLBACK_ABORT;
    }

    return CALLBACK_CONTINUE;
}

static
void
_doYaraScan
(
    HWND hDlg,
    PYARA_OPTIONS yrOpts
)
{
    YR_COMPILER*    yrCompiler          = NULL;
    CHAR            tempPath[MAX_PATH];
    CHAR            tempFile[MAX_PATH];
    CHAR            errFile[MAX_PATH];
    FILE*           ruleFile            = NULL;
    YR_RULES*       yrRules             = NULL;
    int             scanResult          = 0;
    PBYTE           fileData            = NULL;
    int             dataSize            = 0;
    BOOL            success             = FALSE;

    ZeroMemory(tempPath, sizeof(tempPath));
    ZeroMemory(tempFile, sizeof(tempFile));

    __try
    {

        Edit_SetText(GetDlgItem(hDlg, IDC_RESULT), "Running Scan...\r\n\r\n");

        fileData = (PBYTE)CFFApi.eaGetObjectAddress(hDlg);
        dataSize = (int)CFFApi.eaGetObjectSize(hDlg);
        if (NULL == fileData || 0 == dataSize)
        {
            _appendEditBox(hDlg, IDC_RESULT, "ERROR: Invalid data object / len.");
        }
        else if (0 == GetTempPathA(sizeof(tempPath), tempPath))
        {
            _appendEditBox(hDlg, IDC_RESULT, "ERROR: Failed to get temp path.");
        }
        else if (0 == GetTempFileNameA(tempPath, "cff", 0, tempFile) ||
            0 == GetTempFileNameA(tempPath, "err", 0, errFile))
        {
            _appendEditBox(hDlg, IDC_RESULT, "ERROR: Failed to generate a temp file name.");
        }
        else if (FALSE == _saveToFile(tempFile, hDlg, IDC_RULES))
        {
            _appendEditBox(hDlg, IDC_RESULT, "ERROR: Failed to save rules to temp file.");
        }
        else if (0 != fopen_s(&ruleFile,tempFile, "r"))
        {
            _appendEditBox(hDlg, IDC_RESULT, "ERROR: Failed to open temp rules file.");
        }
        else if (ERROR_SUCCESS != yr_compiler_create(&yrCompiler) ||
               (yr_compiler_set_callback(yrCompiler,_compilerCB,(void*)hDlg),FALSE))
        {
            _appendEditBox(hDlg, IDC_RESULT, "Internal Yara error - could not create compiler.");
        }
        else if (0 != yr_compiler_add_file(yrCompiler, ruleFile, NULL, NULL))
        {
            //error in complation
            _appendEditBox(hDlg, IDC_RESULT, "\r\n.. Yara Compile Failed.");
        }
        else if (ERROR_SUCCESS != yr_compiler_get_rules(yrCompiler, &yrRules))
        {
            _appendEditBox(hDlg, IDC_RESULT, "Internal Yara error - could not get rules.");
        }
        else if (ERROR_SUCCESS != (scanResult = yr_rules_scan_mem(yrRules, fileData, dataSize, 0, 
                                            _scanCB, (void*)yrOpts, yrOpts->fastScan ? SCAN_FLAGS_FAST_MODE : 0) ) )
        {
            _appendEditBox(hDlg, IDC_RESULT, "Internal Yara error - scan did not complete successfully.");
        }
        else
        {
            _appendEditBox(hDlg, IDC_RESULT, "\r\n.. Yara Scan Complete!");
            success = TRUE;
        }

        if (!success)
        {
            _appendEditBox(hDlg, IDC_RESULT, "\r\n.. Yara Scan Failed!");
        }

    }
    __finally
    {
        if (NULL != ruleFile)
        {
            fclose(ruleFile);
        }
        if (NULL != yrRules)
        {
            yr_rules_destroy(yrRules);
        }
        if (NULL != yrCompiler)
        {
            yr_compiler_destroy(yrCompiler);
        }

        (void)DeleteFileA(tempFile);
        (void)DeleteFileA(errFile);
    }
}

LRESULT CALLBACK DlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    YARA_OPTIONS    yrOpts = { 0 };
    CHAR            maxRulesStr[5] = { 0 };
    int             maxMatches = 0;

    switch (uMsg)
    {

        case WM_INITDIALOG:
        {
            Edit_LimitText(GetDlgItem(hDlg, IDC_MAXRULES), 3);
            break;
        }

        case WM_COMMAND:
        {
            switch (LOWORD(wParam))
            {
            case IDC_LOADRULES:
            {
                _loadEditBox(hDlg, IDC_RULES, "yara", "*.yara\0\0");
                break;
            }
            case IDC_SAVERULES:
            {
                _saveEditBox(hDlg, IDC_RULES, "yara", "*.yara\0\0");
                break;
            }
            case IDC_SAVERESULT:
            {
                _saveEditBox(hDlg, IDC_RESULT, "txt", ".txt\0\0");
                break;
            }
            case IDC_RUNSCAN:
            {
                yrOpts.hDlg = hDlg;

                if (IsDlgButtonChecked(hDlg, IDC_FASTSCAN) == BST_CHECKED)
                {
                    yrOpts.fastScan = TRUE;
                }
                if (IsDlgButtonChecked(hDlg, IDC_NAMESPACE) == BST_CHECKED)
                {
                    yrOpts.showNamespace = TRUE;
                }
                if (IsDlgButtonChecked(hDlg, IDC_MODULELOADS) == BST_CHECKED)
                {
                    yrOpts.moduleLoad = TRUE;
                }
                if (IsDlgButtonChecked(hDlg, IDC_NONMATCH) == BST_CHECKED)
                {
                    yrOpts.nonMatch = TRUE;
                }
                if (IsDlgButtonChecked(hDlg, IDC_OFFSETS) == BST_CHECKED)
                {
                    yrOpts.offsets = TRUE;
                }

                ZeroMemory(maxRulesStr, sizeof(maxRulesStr));
                Edit_GetText(GetDlgItem(hDlg, IDC_MAXRULES), maxRulesStr, sizeof(maxRulesStr) - 1);

                if (0 < strlen(maxRulesStr))
                {
                    maxMatches = atoi(maxRulesStr);
                    if (maxMatches < 0)
                    {
                        maxMatches = 0;
                    }
                }

                yrOpts.maxMatches = maxMatches;

                _doYaraScan(hDlg, &yrOpts);
                break;
            }
            default:
            {
                break;
            }
            }
        }
    }
    return FALSE;
}