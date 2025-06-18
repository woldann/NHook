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

#ifdef NHOOK_EXPORT
#define NHOOK_API __declspec(dllexport)
#else // !NHOOK_API
#define NHOOK_API __declspec(dllimport)
#endif // !NHOOK_API

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

struct nhook;
struct nhook_manager;
typedef struct nhook nhook_t;
typedef struct nhook_manager nhook_manager_t;

#include <stdint.h>
#include <stdbool.h>
#include <windows.h>

#ifndef __NERROR_H__
#define __NERROR_H__

typedef int nerror_t;

#ifdef NERROR_LEVEL
#undef NERROR_LEVEL
#endif // NERROR_LEVEL

#define NERROR_LEVEL 1

#define N_OK 0x00 // No error
#define N_ERR 0x01 // Generic error code
#define HAS_ERROR(error) (error != N_OK)
#define HAS_ERR(error) (HAS_ERROR(error))

#endif // !__NERROR_H__

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
 * @brief Creates a hook on an already hooked function with custom memory patch
 *
 * This function assumes the target function is already hooked (NHOOK_FLAG_ENABLED).
 * Instead of automatically determining the hook bytes, it uses the provided memory
 * patch and affected length.
 * 
 * @param nhook_manager Hook manager instance
 * @param function Pointer to original function to hook 
 * @param hook_function Pointer to the hook function
 * @param arg_count Number of arguments of the function
 * @param mem Pointer to custom memory patch bytes
 * @param affected_length Length of memory patch in bytes
 * @return nerror_t error code
 */
nerror_t NHOOK_API nh_create_with_mem(nhook_manager_t *nhook_manager,
				      void *function, void *hook_function,
				      uint8_t arg_count, void *mem);

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
 * @brief Creates a hook manager for a specified process ID
 * @param pid Process ID
 * @param max_hook_count Maximum hooks to manage
 * @return Pointer to the newly created hook manager, or NULL on failure
 */
nhook_manager_t *NHOOK_API nh_create_manager(DWORD pid,
					     uint16_t max_hook_count);

/**
 * @brief Destroys the hook manager and releases all associated resources
 * @param nhook_manager Hook manager instance pointer
 */
void NHOOK_API nh_destroy_manager(nhook_manager_t *nhook_manager);

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

#endif // !__NHOOK_H__
