#include <windows.h>

#include "ntutils.h"
#include "nerror.h"

#include "nhook.h"

struct nhook_tfunctions {
	void *VirtualProtect;
	// void *VirtualQuery;
} nh_funcs;

HMODULE nh_get_kernel32_module()
{
	return GetModuleHandleA("kernel32");
}

nerror_t nh_global_init(void)
{
	HMODULE kernel32 = nh_get_kernel32_module();
	if (kernel32 == NULL)
		return GET_ERR(NHOOK_GET_KERNEL32_BASE_ERROR);

	nh_funcs.VirtualProtect =
		GetProcAddress(kernel32, "VirtualProtect");
	// nh_funcs.VirtualQuery = GetProcAddress(libc_base, "VirtualQuery");

	if (nh_funcs.VirtualProtect ==
	    NULL /* || nh_funcs.VirtualQuery == NULL */)
		return GET_ERR(NHOOK_GET_PROC_ADDRESS_ERROR);

	return N_OK;
}

BOOL nh_virtual_protect(LPVOID lpAddress, SIZE_T dwSize,
				  DWORD flNewProtect, PDWORD lpflOldProtect)
{
	ntu_set_default_cc();
	return (BOOL)(int64_t)ntu_ucall(nh_funcs.VirtualProtect, lpAddress,
					dwSize, flNewProtect, lpflOldProtect);
}