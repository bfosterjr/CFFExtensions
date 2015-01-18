#pragma once

#ifndef EXTINITDATA
typedef struct _EXTINITDATA
{
	VOID (__cdecl *RetrieveExtensionApi)(UINT *ApiMask, VOID *pApi);

} EXTINITDATA, *PEXTINITDATA;
#endif