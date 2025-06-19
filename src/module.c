#include "module.h"

#include "nhook.h"

struct nh_tfunctions nh_tfuncs;

HMODULE nh_get_kernel32_module(void)
{
	return GetModuleHandleA("kernel32");
}

nerror_t nh_global_init(void)
{
	HMODULE kernel32 = nh_get_kernel32_module();
	if (kernel32 == NULL)
		return GET_ERR(NHOOK_GET_KERNEL32_BASE_ERROR);

	nh_tfuncs.VirtualProtect = GetProcAddress(kernel32, "VirtualProtect");
	// nh_tfuncs.VirtualQuery = GetProcAddress(libc_base, "VirtualQuery");

	if (nh_tfuncs.VirtualProtect ==
	    NULL /* || nh_tfuncs.VirtualQuery == NULL */)
		return GET_ERR(NHOOK_GET_PROC_ADDRESS_ERROR);

	return N_OK;
}
