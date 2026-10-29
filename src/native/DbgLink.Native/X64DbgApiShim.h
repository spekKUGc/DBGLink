#pragma once
// X64DbgApiShim.h — test-only x64dbg bridge shim for DbgLink.Native.Tests.
//
// The product handlers resolve every x64dbg entry point dynamically through
// GetDebuggerBridgeFunction() (NativeBridgeFoundation.h), which is
// GetModuleHandleW(DebuggerBridgeModuleName()) + GetProcAddress().  This
// header redirects those two Win32 calls — via the macros at the bottom — to
// the scripted implementations in X64DbgApiShim.cpp, so the handlers link and
// run inside the test executable with no live x64dbg.
//
// Activation: the test vcxproj force-includes this header (/FI) for every
// product TU it compiles, and the test TUs include it explicitly.  Product
// sources are NOT modified.  X64DbgApiShim.cpp undefines the macros right
// after including this header so it can forward non-bridge calls to the real
// Win32 APIs.
//
// Scripted surface: IsDebugging/IsRunning flags, a register/expression file
// (DbgValFromString/DbgValToString/DbgIsValidExpression), a byte-addressed
// memory image (DbgMemRead/DbgMemWrite), MEM_IMAGE pages (DbgMemMap,
// DbgMemFindBaseAddr), module/label/comment text, a breakpoint store with an
// ExecDirect engine that applies bp/bc/bph/bpm edits (DbgGetBpList), a thread
// list with switchthread support (DbgGetThreadList), fixed disassembly
// (DbgDisasmFastAt), xref data (DbgGetXrefCountAt/DbgXrefGet) and an
// ExecDirect log with scripted accept/reject rules.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "NativeTypes.h"

namespace dbglink
{
    namespace testshim
    {
        // Drops all scripted state, clears the ExecDirect log, disarms any
        // in-flight CallFunction restore, clears the N1 session token and the
        // rendezvous-path override, and bumps g_debuggerGeneration so a
        // stale CollectModuleRecords cache cannot leak across tests.
        void Reset();
        void SetDebugging(bool debugging);
        void SetRunning(bool running);

        // Registers and arbitrary expressions for DbgValFromString.  Names are
        // matched case-insensitively.  SetRegister also marks the name as a
        // valid (possibly zero-valued) expression.
        void SetRegister(const std::string& name, std::uintptr_t value);
        void SetExpression(const std::string& expression, std::uintptr_t value);
        void SetExpressionValid(const std::string& expression, bool valid);
        // DbgValToString writes the register file; false simulates a debugger
        // that rejects the write.
        void SetValToStringResult(bool ok);
        // DbgMemWrite result flag; the image is updated only on success.
        void SetMemWriteResult(bool ok);

        // Byte-addressed memory image.  Reads fail when any byte is missing;
        // writes always extend the image (unless SetMemWriteResult(false)).
        void WriteImage(std::uintptr_t address, const void* data, std::size_t size);
        void WriteImageBytes(std::uintptr_t address, const std::vector<unsigned char>& data);
        void WriteImageString(std::uintptr_t address, const char* text);
        void WriteImageString16(std::uintptr_t address, const char* asciiText);
        bool ReadImageByte(std::uintptr_t address, unsigned char& value);
        void ClearImage();

        // DbgMemMap / DbgMemFindBaseAddr pages.
        struct FakePage
        {
            MEMORY_BASIC_INFORMATION mbi{};
            std::string info;
        };
        FakePage MakeImagePage(
            std::uintptr_t base,
            std::size_t size,
            DWORD protect = PAGE_EXECUTE_READ,
            const std::string& info = {});
        void SetMemoryPages(std::vector<FakePage> pages);
        void SetMemMapResult(bool ok);

        // DbgGetModuleAt / DbgGetLabelAt / DbgGetCommentAt text.  Module
        // lookup picks the greatest scripted base at or below the address.
        void SetModuleName(std::uintptr_t base, const std::string& name);
        void SetLabelText(std::uintptr_t address, const std::string& text);
        void SetCommentText(std::uintptr_t address, const std::string& text);

        // DbgGetBpList store.  `type` uses the BpListType values (1 = soft,
        // 2 = hardware, 4 = memory); anything else reads back as empty.
        void AddBreakpoint(
            int type,
            std::uintptr_t address,
            const std::string& name = {},
            bool singleshoot = false);
        void ClearBreakpoints();

        // DbgGetThreadList store.
        BRIDGE_THREAD_ALL_INFO MakeThread(
            int number,
            DWORD threadId,
            std::uintptr_t entry,
            const std::string& name = {});
        void SetThreads(std::vector<BRIDGE_THREAD_ALL_INFO> threads, int currentThread);

        // DbgDisasmFastAt: every address disassembles to the same fixed
        // instruction (size <= 0 renders as <undecodable>).
        void SetDisasm(const std::string& text, int size);

        // DbgGetXrefCountAt / DbgXrefGet data.
        struct FakeXref
        {
            std::uintptr_t from = 0;
            XrefType type = XrefType::Call;
        };
        void SetXrefCount(std::uintptr_t target, std::uintptr_t count);
        void SetXrefs(std::uintptr_t target, std::vector<FakeXref> refs);

        // DbgCmdExecDirect log and result policy.
        const std::vector<std::string>& ExecLog();
        void ClearExecLog();
        void SetExecDirectResult(bool ok);
        // Any command containing `text` fails (used for bpc/bpl-failure and
        // rollback tests).  Empty text disables the rule.
        void SetExecRejectContains(const std::string& text);

        // DbgGetProcessHandle value (default nullptr: ProcessModulePath then
        // falls back to the scripted module names).
        void SetProcessHandle(HANDLE handle);

        // Bridge-proc lookup used by the GetProcAddress redirection below.
        // Defined in X64DbgApiShim.cpp; returns nullptr for unknown names.
        FARPROC LookupBridgeProc(const char* name);
    } // namespace testshim
} // namespace dbglink

// Bridge-call redirection.  Declared after <windows.h> so the signatures
// match the real APIs exactly (same WINAPI convention on x86).
HMODULE WINAPI DbglinkTestShimGetModuleHandleW(_In_opt_ LPCWSTR lpModuleName);
FARPROC WINAPI DbglinkTestShimGetProcAddress(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
#define GetModuleHandleW DbglinkTestShimGetModuleHandleW
#define GetProcAddress DbglinkTestShimGetProcAddress
