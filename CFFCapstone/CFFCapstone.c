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
    lvc.cx = PIXELS_PER_CHAR * sizeof("   Instruction   ");
    ListView_InsertColumn(GetDlgItem(hDlg, IDC_DISM_OUTPUT), 0, &lvc);
    ListView_SetColumnWidth(GetDlgItem(hDlg, IDC_DISM_OUTPUT), 0, LVSCW_AUTOSIZE_USEHEADER);


    ZeroMemory(&lvc, sizeof(lvc));
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = "   OpCode   ";
    lvc.cx = PIXELS_PER_CHAR * sizeof("   OpCpde   ");
    ListView_InsertColumn(GetDlgItem(hDlg, IDC_DISM_OUTPUT), 0, &lvc);
    ListView_SetColumnWidth(GetDlgItem(hDlg, IDC_DISM_OUTPUT), 0, LVSCW_AUTOSIZE_USEHEADER);

    ZeroMemory(&lvc, sizeof(lvc));
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = "   Offset   ";
    lvc.cx = PIXELS_PER_CHAR * sizeof("   Offset   ");
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

    switch (uMsg)
    {

        case WM_INITDIALOG:
        {
            if (g_object != CFFApi.eaGetObjectAddress(hDlg))
            {
                g_object = (PBYTE) CFFApi.eaGetObjectAddress(hDlg);
                g_objectSize = (DWORD)CFFApi.eaGetObjectSize(hDlg);
            }
            //TODO: add these back in..
            //ComboBox_ResetContent(GetDlgItem(hDlg, IDC_ARCH_TYPE));
            //ComboBox_AddString(GetDlgItem(hDlg, IDC_ARCH_TYPE), "ARM");
            //ComboBox_AddString(GetDlgItem(hDlg, IDC_ARCH_TYPE), "ARM64");
            //ComboBox_AddString(GetDlgItem(hDlg, IDC_ARCH_TYPE), "MIPS");
            ComboBox_AddString(GetDlgItem(hDlg, IDC_ARCH_TYPE), "x86 / x64");
            //ComboBox_AddString(GetDlgItem(hDlg, IDC_ARCH_TYPE), "PPC");
            //ComboBox_AddString(GetDlgItem(hDlg, IDC_ARCH_TYPE), "SPARC");
            //ComboBox_AddString(GetDlgItem(hDlg, IDC_ARCH_TYPE), "SPARC");
            //set x86/x64 as default
            ComboBox_SetCurSel(GetDlgItem(hDlg, IDC_ARCH_TYPE), /*3*/ 0);

            _setViewColums(hDlg);
            break;
        }

        case WM_COMMAND:
        {
            switch (LOWORD(wParam))
            {
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
                else if (CS_ERR_OK != (cap_err = cs_open(/*(cs_arch)arch_index*/CS_ARCH_X86, 0, &capstone_hndl)))
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