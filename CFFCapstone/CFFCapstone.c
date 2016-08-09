#include <Windows.h>
#include <Windowsx.h>
#include <stdlib.h>
#include "CFFExplorerSDK.h"
#include "Extension.h"
#include "resource.h"
#include "Commctrl.h"
#include "capstone.h"


#define MAX_LABEL_LEN   20
#define MAX_HASH_ITEMS  50
#define MAX_URL_LEN     128


PBYTE       g_object        = NULL;
DWORD       g_objectSize    = 0;

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
    return L"Capstone";
}

__declspec(dllexport) WCHAR * __cdecl ExtensionDescription()
{
    return L"Disassembly via Capstone";
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
    HANDLE  hFile = INVALID_HANDLE_VALUE;
    int     listCount = 0;
    int     i = 0;
    CHAR    full_str[256] = { 0 };
    int     len = 0;
    DWORD   bytesWritten = 0;
    PCHAR   lineFeed = "\r\n";
    LVITEM  lvi = { 0 };
    CHAR    addr_str[11] = { 0 };
    CHAR    bytesStr[17] = { 0 };
    CHAR    inst_str[200] = { 0 };

    __try
    {
        hFile = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE,
            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (INVALID_HANDLE_VALUE != hFile)
        {
            if (0 < (listCount = (int)ListView_GetItemCount(GetDlgItem(hDlg, IDC_DISM_OUTPUT))))
            {
                for (i = 0; i < listCount; i++)
                {
                    ZeroMemory(addr_str, sizeof(addr_str));
                    lvi.mask = LVIF_TEXT;
                    lvi.iItem = i;
                    lvi.iSubItem = 0;
                    lvi.cchTextMax = sizeof(addr_str);
                    lvi.pszText = addr_str;
                    SendDlgItemMessageA(hDlg, IDC_DISM_OUTPUT, LVM_GETITEMTEXT, i, (LPARAM)&lvi);

                    ZeroMemory(bytesStr, sizeof(bytesStr));
                    lvi.mask = LVIF_TEXT;
                    lvi.iItem = i;
                    lvi.iSubItem = 1;
                    lvi.cchTextMax = sizeof(bytesStr);
                    lvi.pszText = bytesStr;
                    SendDlgItemMessageA(hDlg, IDC_DISM_OUTPUT, LVM_GETITEMTEXT, i, (LPARAM)&lvi);

                    ZeroMemory(inst_str, sizeof(inst_str));
                    lvi.mask = LVIF_TEXT;
                    lvi.iItem = i;
                    lvi.iSubItem = 2;
                    lvi.cchTextMax = sizeof(inst_str);
                    lvi.pszText = inst_str;
                    SendDlgItemMessageA(hDlg, IDC_DISM_OUTPUT, LVM_GETITEMTEXT, i, (LPARAM)&lvi);

                    ZeroMemory(full_str, sizeof(full_str));
                    _snprintf_s(full_str, sizeof(full_str), sizeof(full_str), "%s\t%16s\t%s",
                        addr_str, bytesStr, inst_str);
                    
                    WriteFile(hFile, full_str, (DWORD) strlen(full_str), &bytesWritten, NULL);
                    WriteFile(hFile, lineFeed, 2, &bytesWritten, NULL);
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
_output_instruction
(
    HWND        hDlg,
    cs_insn*    capstone_inst,
    int         index
)
{
    LV_ITEMA lvi = { 0 };
    CHAR    temp_str[33] = { 0 };
    CHAR*   temp_ptr = &(temp_str[0]);
    int     subitem = 0;
    DWORD   i = 0;
    DWORD   num_convert = 0;
    CHAR    complete_inst_str[256] = { 0 };

    ZeroMemory(&lvi, sizeof(lvi));
    ZeroMemory(temp_str, sizeof(temp_str));
    //TODO: avoid this down cast..
    _snprintf_s(temp_str, sizeof(temp_str), sizeof(temp_str), "0x%08X", (DWORD)capstone_inst->address);

    lvi.mask = LVIF_TEXT;
    lvi.pszText = temp_str;
    lvi.cchTextMax = sizeof(temp_str);
    lvi.iItem = index;
    lvi.iSubItem = subitem;
    SendDlgItemMessageA(hDlg, IDC_DISM_OUTPUT, subitem == 0 ? LVM_INSERTITEMA : LVM_SETITEMA, 0, (LPARAM)&lvi);
    subitem++;

    ZeroMemory(&lvi, sizeof(lvi));
    ZeroMemory(temp_str, sizeof(temp_str));
    for (i = 0; i < capstone_inst->size; i++)
    {
        num_convert = _snprintf_s(temp_ptr, sizeof(temp_str) - i, 2, "%02X", (DWORD)capstone_inst->bytes[i]);
        temp_ptr += num_convert;
        if (-1 == num_convert)
            break;
    }
    lvi.mask = LVIF_TEXT;
    lvi.pszText = temp_str;
    lvi.cchTextMax = sizeof(temp_str);
    lvi.iItem = index;
    lvi.iSubItem = subitem;
    SendDlgItemMessageA(hDlg, IDC_DISM_OUTPUT, subitem == 0 ? LVM_INSERTITEMA : LVM_SETITEMA, 0, (LPARAM)&lvi);
    subitem++;

    ZeroMemory(complete_inst_str, sizeof(complete_inst_str));
    ZeroMemory(&lvi, sizeof(lvi));
    _snprintf_s(complete_inst_str, sizeof(complete_inst_str), sizeof(complete_inst_str), "%s %s",
        capstone_inst->mnemonic, capstone_inst->op_str);
    lvi.mask = LVIF_TEXT;
    lvi.pszText = complete_inst_str;
    lvi.cchTextMax = sizeof(complete_inst_str);
    lvi.iItem = index;
    lvi.iSubItem = subitem;
    SendDlgItemMessageA(hDlg, IDC_DISM_OUTPUT, subitem == 0 ? LVM_INSERTITEMA : LVM_SETITEMA, 0, (LPARAM)&lvi);
    subitem++;

}

static
void
_do_disasm
(
    HWND    hDlg,
    csh     capstone_hndl,
    DWORD   offset,
    DWORD   length
)
{
    int         index           = 0;
    PBYTE       code            = (PBYTE)g_object + offset;
    SIZE_T      code_len        = length;
    uint64_t    address         = 0;
    cs_insn     capstone_inst   = { 0 };


    while (cs_disasm_iter(capstone_hndl, &code, &code_len, &address, &capstone_inst))
    {
        _output_instruction(hDlg, &capstone_inst, index);
        index++;
    }
}

#define PIXELS_PER_CHAR     6

static
void
_setViewColums
(
    HWND hDlg
)
{
    LV_COLUMNA lvc = { 0 };

    ListView_SetExtendedListViewStyle(GetDlgItem(hDlg, IDC_DISM_OUTPUT), LVS_EX_FULLROWSELECT);

    ZeroMemory(&lvc, sizeof(lvc));
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = "   Instruction   ";
    lvc.cx = PIXELS_PER_CHAR * sizeof("    Instruction    ");
    ListView_InsertColumn(GetDlgItem(hDlg, IDC_DISM_OUTPUT), 0, &lvc);
    ListView_SetColumnWidth(GetDlgItem(hDlg, IDC_DISM_OUTPUT), 0, LVSCW_AUTOSIZE_USEHEADER);


    ZeroMemory(&lvc, sizeof(lvc));
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = "   OpCode   ";
    lvc.cx = PIXELS_PER_CHAR * sizeof("     OpCpde     ");
    ListView_InsertColumn(GetDlgItem(hDlg, IDC_DISM_OUTPUT), 0, &lvc);
    ListView_SetColumnWidth(GetDlgItem(hDlg, IDC_DISM_OUTPUT), 0, LVSCW_AUTOSIZE_USEHEADER);

    ZeroMemory(&lvc, sizeof(lvc));
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = "   Offset   ";
    lvc.cx = PIXELS_PER_CHAR * sizeof("     Offset     ");
    ListView_InsertColumn(GetDlgItem(hDlg, IDC_DISM_OUTPUT), 0, &lvc);
    ListView_SetColumnWidth(GetDlgItem(hDlg, IDC_DISM_OUTPUT), 0, LVSCW_AUTOSIZE_USEHEADER);


}

LRESULT CALLBACK DlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    int     i               = 0;
    int     list_index      = 0;
    int     idata           = 0;
    char    offset[16]      = { 0 };
    char    length[16]      = { 0 };
    int     offsetval       = 0;
    int     lengthval       = 0;
    char*   temp            = NULL;
    char    lang[4]         = { 0 };
    csh     capstone_hndl   = 0;
    cs_err  cap_err         = CS_ERR_OK;
    int     arch_index      = 0;
    int     x86_index       = 0;
    char            saveFilePath[MAX_PATH];
    OPENFILENAMEA   saveFile;

    switch (uMsg)
    {

        case WM_INITDIALOG:
        {
            if (g_object != CFFApi.eaGetObjectAddress(hDlg))
            {
                g_object = (PBYTE) CFFApi.eaGetObjectAddress(hDlg);
                g_objectSize = (DWORD)CFFApi.eaGetObjectSize(hDlg);
            }
            //Setup the asm types
            ComboBox_ResetContent(GetDlgItem(hDlg, IDC_ARCH_TYPE));
            ComboBox_AddString(GetDlgItem(hDlg, IDC_ARCH_TYPE), "ARM");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_ARCH_TYPE), "ARM64");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_ARCH_TYPE), "MIPS");
            x86_index = ComboBox_AddString(GetDlgItem(hDlg, IDC_ARCH_TYPE), "x86 / x64");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_ARCH_TYPE), "PPC");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_ARCH_TYPE), "SPARC");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_ARCH_TYPE), "SPARC");
            //set x86/x64 as default
            ComboBox_SetCurSel(GetDlgItem(hDlg, IDC_ARCH_TYPE), x86_index);

            //Setup the asm types
            ComboBox_ResetContent(GetDlgItem(hDlg, IDC_MODE_TYPE));
            x86_index = ComboBox_AddString(GetDlgItem(hDlg, IDC_MODE_TYPE), "Little-Endian");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_MODE_TYPE), "32-bit ARM");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_MODE_TYPE), "16-bit mode (x86)");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_MODE_TYPE), "32-bit mode (x86)");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_MODE_TYPE), "64-bit mode (x86,PPC)");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_MODE_TYPE), "ARM THUMB(2)");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_MODE_TYPE), "ARM MClass (Cortex-M)");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_MODE_TYPE), "ARMv8 A32");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_MODE_TYPE), "MICRO (MIPS)");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_MODE_TYPE), "MIPS III");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_MODE_TYPE), "MIPS32R6");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_MODE_TYPE), "MIPSGP64");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_MODE_TYPE), "V9 (Sparc)");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_MODE_TYPE), "Big-Endian");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_MODE_TYPE), "Mips32");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_MODE_TYPE), "Mips64");

            //set Little Endian as default
            ComboBox_SetCurSel(GetDlgItem(hDlg, IDC_MODE_TYPE), x86_index);

            _setViewColums(hDlg);
            break;
        }

        case WM_COMMAND:
        {
            switch (LOWORD(wParam))
            {
            case IDC_SAVE:
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
                break;
            }
            case IDC_DO_DISM:
            {
                arch_index = ComboBox_GetCurSel(GetDlgItem(hDlg, IDC_ARCH_TYPE));
                ZeroMemory(offset, sizeof(offset));
                ZeroMemory(length, sizeof(length));
                Edit_GetText(GetDlgItem(hDlg, IDC_OFFSET), offset, sizeof(offset) - 1);
                Edit_GetText(GetDlgItem(hDlg, IDC_LENGTH), length, sizeof(length) - 1);
                if (strlen(offset) > 0 && strlen(length) > 0)
                {
                    offsetval = strtol(offset, &temp, 16);
                    lengthval = strtol(length, &temp, 16);
                }
                if (lengthval == 0 || (DWORD)(offsetval + lengthval) > g_objectSize)
                {

                }
                else if (CS_ERR_OK != (cap_err = cs_open(arch_index, 0, &capstone_hndl)))
                {

                }
                else
                {
                    _do_disasm(hDlg, capstone_hndl, offsetval, lengthval);
                    (void)cs_close(&capstone_hndl);
                }
                break;
            }
            }
            break;
        }
    }
    return FALSE;
}