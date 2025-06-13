/**
 * MIT License
 *
 * Copyright (c) 2025 Serkan Aksoy
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __NHOOK_H__
#define __NHOOK_H__

#ifndef NHOOK_API
#define NHOOK_API NTHREAD_API
#endif // NHOOK_API

#ifdef NHOOK_EXPORTS

#ifndef NTHREAD_API
#define NTHREAD_API __declspec(dllexport)
#endif // !NTHREAD_API

#ifndef LOG_API
#define LOG_API __declspec(dllexport)
#endif // !LOG_API

#else // !NHOOK_EXPORTS

#define NTHREAD_API __declspec(dllimport)
#define LOG_API __declspec(dllimport)

#endif // !NHOOK_EXPORTS

#include "ntosutils.h"

#define NHOOK_ERROR 0x4500
#define NHOOK_FIND_ERROR 0x4501
#define NHOOK_REALLOC_ERROR 0x4502
#define NHOOK_MAX_HOOK_ERROR 0x4503
#define NHOOK_NTU_READ_MEMORY_ERROR 0x4505
#define NHOOK_CS_OPEN_ERROR 0x4506
#define NHOOK_GET_KERNEL32_BASE_ERROR 0x4507
#define NHOOK_GET_PROC_ADDRESS_ERROR 0x4508
#define NHOOK_NTU_MALLOC_ERROR 0x4509
#define NHOOK_NOSU_UPGRADE_ERROR 0x450A
#define NHOOK_NOSU_ATTACH_ERROR 0x450B
#define NHOOK_NH_UPDATE_THREAD_ERROR 0x450C
#define NHOOK_NH_SUSPEND_THREADS_ERROR 0x450D
#define NHOOK_NH_RESUME_THREADS_ERROR 0x450E
#define NHOOK_NH_TOGGLE_INIT_ERROR 0x450F
#define NHOOK_CS_DETAIL_ERROR 0x4510
#define NHOOK_TRAMPOLINE_INIT_ERROR 0x4511
#define NHOOK_ADD_INSN_ERROR 0x4512
#define NHOOK_CS_OPTION_ERROR 0x4513

#define NHOOK_FLAG_ENABLED 0x01
#define NHOOK_FLAG_SECOND_INSN 0x02

/**
 * @brief Represents an inline hook instance
 * 
 * Contains the original function address, hook function address, calling convention,
 * flags, argument count, overwritten instruction bytes, and trampoline address.
 */
struct trampoline;

struct nhook {
	void *function; /**< Address of the original function */
	void *hook_function; /**< Address of the hook function */

#ifndef NTU_GLOBAL_CC
	ntucc_t cc; /**< Calling convention */
#endif // !NTU_GLOBAL_CC

	int8_t flags; /**< Hook flags (e.g. enabled) */
	uint8_t arg_count; /**< Number of arguments the function accepts */

	uint8_t affected_length; /**< Number of bytes overwritten in original function */
	uint8_t mem[16]; /**< Backup of overwritten instruction bytes */

	void *tramp; /**< Trampoline function pointer */
};

typedef struct nhook nhook_t;

/**
 * @brief Marks a hook as invalid (clears its function pointer)
 * @param nhook Pointer to hook instance
 */
#define NHOOK_SET_INVALID(nhook) ((nhook)->function = NULL)

/**
 * @brief Checks whether a hook is valid (has a non-null function pointer)
 * @param nhook Pointer to hook instance
 * @return true if valid, false otherwise
 */
#define NHOOK_IS_VALID(nhook) ((nhook)->function != NULL)

/**
 * @brief Manages all hooks and thread states for a specific process
 * 
 * Keeps track of process ID, synchronization mutex, thread handles and IDs,
 * counts of threads and hooks, and suspension counts.
 */
struct nhook_manager {
	DWORD pid; /**< Process ID */

	NMUTEX mutex; /**< Mutex for thread-safe operations */

	ntid_t *o_thread_ids; /**< Original thread IDs before hooking */
	ntid_t *n_thread_ids; /**< New thread IDs after hooking */
	size_t thread_ids_size; /**< Size of thread ID arrays */

	HANDLE *threads; /**< Handles to the threads */
	uint16_t thread_count; /**< Number of threads */
	uint16_t suspend_count; /**< Number of suspended threads */

	uint16_t max_hook_count; /**< Maximum number of hooks allowed */
};

typedef struct nhook_manager nhook_manager_t;

/**
 * @brief Helper macro to get a hook by index from the hook manager
 */
#define NHOOK_MANAGER_GET_HOOK(nhook_manager, index) \
	(((nhook_t *)(((nhook_manager) + 1))) + i)

/**
 * @brief Retrieves the base address of kernel32.dll in the target process
 * @return Pointer to kernel32.dll base, or NULL on failure
 */
void *NHOOK_API nh_get_kernel32_base();

/**
 * @brief Initializes global resources needed for hooking
 * @return nerror_t error code, 0 on success
 */
nerror_t NHOOK_API nh_global_init();

/**
 * @brief Changes the protection attributes of a memory region
 * @param lpAddress Starting address of region
 * @param dwSize Size of the region in bytes
 * @param flNewProtect New protection flags (e.g. PAGE_EXECUTE_READWRITE)
 * @param lpflOldProtect Out parameter to receive old protection flags
 * @return TRUE on success, FALSE on failure
 */
BOOL NHOOK_API nh_virtual_protect(LPVOID lpAddress, SIZE_T dwSize,
				  DWORD flNewProtect, PDWORD lpflOldProtect);

/**
 * @brief Checks whether a hook is currently enabled (extended)
 * @param nhook Pointer to hook instance
 * @return true if enabled, false otherwise
 */
bool NHOOK_API nh_is_enabled_ex(nhook_t *nhook);

/**
 * @brief Checks whether a hook function is enabled within the hook manager
 * @param nhook_manager Hook manager instance
 * @param hook_function Pointer to hook function
 * @return true if enabled, false otherwise
 */
bool NHOOK_API nh_is_enabled(nhook_manager_t *nhook_manager,
			     void *hook_function);

/**
 * @brief Finds a hook by original function address
 * @param nhook_manager Hook manager instance
 * @param function Pointer to the original function
 * @return Pointer to nhook instance if found, NULL otherwise
 */
nhook_t *NHOOK_API nh_find_with_function(nhook_manager_t *nhook_manager,
					 void *function);

/**
 * @brief Finds a hook by hook function address
 * @param nhook_manager Hook manager instance
 * @param hook_function Pointer to the hook function
 * @return Pointer to nhook instance if found, NULL otherwise
 */
nhook_t *NHOOK_API nh_find(nhook_manager_t *nhook_manager, void *hook_function);

/**
 * @brief Creates a hook manager for a specified process ID
 * @param pid Process ID
 * @param max_hook_count Maximum hooks to manage
 * @return Pointer to the newly created hook manager, or NULL on failure
 */
nhook_manager_t *NHOOK_API nh_create_manager(DWORD pid,
					     uint16_t max_hook_count);

/**
 * @brief Gets the count of currently enabled hooks in the manager
 * @param nhook_manager Hook manager instance
 * @return Number of enabled hooks
 */
uint16_t NHOOK_API nh_manager_get_enabled_count(nhook_manager_t *nhook_manager);

/**
 * @brief Gets the total number of hooks in the manager
 * @param nhook_manager Hook manager instance
 * @return Total number of hooks
 */
uint16_t NHOOK_API nh_manager_get_count(nhook_manager_t *nhook_manager);

/**
 * @brief Creates a hook on the specified function
 * @param nhook_manager Hook manager instance
 * @param function Pointer to original function to hook
 * @param hook_function Pointer to the hook function
 * @param arg_count Number of arguments of the function
 * @return nerror_t error code
 */
nerror_t NHOOK_API nh_create(nhook_manager_t *nhook_manager, void *function,
			     void *hook_function, uint8_t arg_count);

/**
 * @brief Enables a specific hook (extended version)
 * @param nhook_manager Hook manager instance
 * @param nhook Pointer to hook instance
 * @return nerror_t error code
 */
nerror_t NHOOK_API nh_enable_ex(nhook_manager_t *nhook_manager, nhook_t *nhook);

/**
 * @brief Enables a hook by hook function pointer
 * @param nhook_manager Hook manager instance
 * @param hook_function Pointer to hook function to enable
 * @return nerror_t error code
 */
nerror_t NHOOK_API nh_enable(nhook_manager_t *nhook_manager,
			     void *hook_function);

/**
 * @brief Enables all hooks managed by the manager
 * @param nhook_manager Hook manager instance
 * @return nerror_t error code
 */
nerror_t NHOOK_API nh_enable_all(nhook_manager_t *nhook_manager);

/**
 * @brief Disables a specific hook (extended version)
 * @param nhook_manager Hook manager instance
 * @param nhook Pointer to hook instance
 * @return nerror_t error code
 */
nerror_t NHOOK_API nh_disable_ex(nhook_manager_t *nhook_manager,
				 nhook_t *nhook);

/**
 * @brief Disables a hook by hook function pointer
 * @param nhook_manager Hook manager instance
 * @param hook_function Pointer to hook function to disable
 * @return nerror_t error code
 */
nerror_t NHOOK_API nh_disable(nhook_manager_t *nhook_manager,
			      void *hook_function);

/**
 * @brief Disables all hooks managed by the manager
 * @param nhook_manager Hook manager instance
 * @return nerror_t error code
 */
nerror_t NHOOK_API nh_disable_all(nhook_manager_t *nhook_manager);

/**
 * @brief Destroys a specific hook (extended version)
 * @param nhook_manager Hook manager instance
 * @param nhook Pointer to hook instance to destroy
 */
void NHOOK_API nh_destroy_ex(nhook_manager_t *nhook_manager, nhook_t *nhook);

/**
 * @brief Destroys a hook by hook function pointer
 * @param nhook_manager Hook manager instance
 * @param hook_function Pointer to hook function to destroy
 */
void NHOOK_API nh_destroy(nhook_manager_t *nhook_manager, void *hook_function);

/**
 * @brief Destroys all hooks managed by the manager
 * @param nhook_manager Hook manager instance
 */
void NHOOK_API nh_destroy_all(nhook_manager_t *nhook_manager);

/**
 * @brief Resumes all suspended threads in the hooked process
 * @param nhook_manager Hook manager instance
 * @return nerror_t error code
 */
nerror_t NHOOK_API nh_resume_threads(nhook_manager_t *nhook_manager);

/**
 * @brief Suspends all threads in the hooked process
 * @param nhook_manager Hook manager instance
 * @return nerror_t error code
 */
nerror_t NHOOK_API nh_suspend_threads(nhook_manager_t *nhook_manager);

/**
 * @brief Calls the original function (trampoline) with a va_list of arguments (extended)
 * 
 * This is used within the hook function to call the original, unhooked function,
 * forwarding the argument list.
 * 
 * @param nhook_manager Hook manager instance
 * @param nhook Pointer to hook instance
 * @param args va_list arguments to pass to original function
 * @return Return value of the original function cast to void*
 */
void *NHOOK_API nh_trampoline_ex_v(nhook_manager_t *nhook_manager,
				   nhook_t *nhook, va_list args);

/**
 * @brief Calls the original function (trampoline) with variable arguments (extended)
 * 
 * Variadic convenience wrapper around nh_trampoline_ex_v.
 * 
 * @param nhook_manager Hook manager instance
 * @param nhook Pointer to hook instance
 * @param ... Variable arguments for the original function
 * @return Return value of the original function cast to void*
 */
void *NHOOK_API nh_trampoline_ex(nhook_manager_t *nhook_manager, nhook_t *nhook,
				 ...);

/**
 * @brief Calls the original function (trampoline) by hook function pointer with va_list
 * 
 * Finds the hook by hook function pointer and calls the original function with va_list args.
 * 
 * @param nhook_manager Hook manager instance
 * @param hook_function Pointer to hook function
 * @param args va_list arguments
 * @return Return value of the original function cast to void*
 */
void *NHOOK_API nh_trampoline_v(nhook_manager_t *nhook_manager,
				void *hook_function, va_list args);

/**
 * @brief Calls the original function (trampoline) by hook function pointer with variable arguments
 * 
 * Convenience variadic wrapper to call the trampoline using hook function pointer.
 * 
 * @param nhook_manager Hook manager instance
 * @param hook_function Pointer to hook function
 * @param ... Variable arguments for the original function
 * @return Return value of the original function cast to void*
 */
void *NHOOK_API nh_trampoline(nhook_manager_t *nhook_manager,
			      void *hook_function, ...);

/**
 * @brief Updates thread states and hook statuses
 * 
 * This function must be called regularly (e.g. in a loop) to activate hooks and
 * synchronize thread suspensions/resumptions.
 * Without calling this, hooks will not become active or behave properly.
 * 
 * @param nhook_manager Hook manager instance
 * @return nerror_t error code
 */
nerror_t NHOOK_API nh_update(nhook_manager_t *nhook_manager);

/**
 * @brief Destroys the hook manager and releases all associated resources
 * @param nhook_manager Hook manager instance pointer
 */
void NHOOK_API nh_destroy_manager(nhook_manager_t *nhook_manager);

#endif // !__NHOOK_H__
