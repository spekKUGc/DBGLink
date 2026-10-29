#include "X64DbgApiShim.h"
#ifdef GetModuleHandleW
#undef GetModuleHandleW
#endif
#ifdef GetProcAddress
#undef GetProcAddress
#endif
#include "NativeBridgeFoundation.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <utility>

// X64DbgApiShim.cpp — scripted x64dbg bridge for unit tests.  Compiled only
// into DbgLink.Native.Tests (never into the product plugin).  See the header
// for the activation mechanism (forced include + macro redirection).

namespace dbglink
{
    namespace testshim
    {
        namespace
        {
            std::string LowerAscii(const std::string& text)
            {
                std::string result = text;
                for (char& c : result)
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                return result;
            }

            bool ParseHexToken(const std::string& text, std::size_t from, std::uintptr_t& value)
            {
                value = 0;
                std::size_t digits = 0;
                for (std::size_t i = from; i < text.size(); ++i)
                {
                    const char c = text[i];
                    unsigned digit = 0;
                    if (c >= '0' && c <= '9')
                        digit = static_cast<unsigned>(c - '0');
                    else if (c >= 'a' && c <= 'f')
                        digit = static_cast<unsigned>(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F')
                        digit = static_cast<unsigned>(c - 'A' + 10);
                    else
                        break;
                    if (digits >= sizeof(std::uintptr_t) * 2)
                        return false;
                    value = value * 16 + digit;
                    ++digits;
                }
                return digits > 0;
            }

            // First 0x-prefixed address in a command line, if any.
            bool CommandAddress(const std::string& command, std::uintptr_t& address)
            {
                for (std::size_t i = 0; i + 2 < command.size(); ++i)
                {
                    if (command[i] == '0' && (command[i + 1] == 'x' || command[i + 1] == 'X'))
                    {
                        if (ParseHexToken(command, i + 2, address))
                            return true;
                    }
                }
                return false;
            }

            struct State
            {
                bool debugging = false;
                bool running = false;
                std::unordered_map<std::string, std::uintptr_t> registers;
                std::unordered_map<std::string, std::uintptr_t> expressions;
                std::unordered_set<std::string> validExpressions;
                bool valToStringResult = true;
                bool memWriteResult = true;
                std::map<std::uintptr_t, unsigned char> image;
                std::vector<FakePage> pages;
                bool memMapResult = true;
                std::map<std::uintptr_t, std::string> moduleNames;
                std::unordered_map<std::uintptr_t, std::string> labels;
                std::unordered_map<std::uintptr_t, std::string> comments;
                struct BpEntry
                {
                    std::uintptr_t address = 0;
                    std::string name;
                    bool singleshoot = false;
                };
                std::map<int, std::vector<BpEntry>> breakpoints;
                std::vector<BRIDGE_THREAD_ALL_INFO> threads;
                int currentThread = 0;
                std::string disasmText = "nop";
                int disasmSize = 1;
                std::unordered_map<std::uintptr_t, std::uintptr_t> xrefCounts;
                std::unordered_map<std::uintptr_t, std::vector<FakeXref>> xrefs;
                std::vector<std::string> execLog;
                bool execDirectResult = true;
                std::string execRejectContains;
                HANDLE processHandle = nullptr;
            };

            State& GetState()
            {
                static State state;
                return state;
            }

            std::string ModuleNameAt(std::uintptr_t address)
            {
                const auto& names = GetState().moduleNames;
                auto it = names.upper_bound(address);
                if (it == names.begin())
                    return {};
                --it;
                return it->second;
            }

            void CopyCapped(char* destination, const std::string& text)
            {
                // All product call sites pass at least 256 bytes.
                strncpy_s(destination, 256, text.c_str(), _TRUNCATE);
            }

            // ---- Dbg* implementations (signatures mirror NativeTypes.h) ----
            bool __cdecl ShimDbgIsDebugging() { return GetState().debugging; }
            bool __cdecl ShimDbgIsRunning() { return GetState().running; }

            std::uintptr_t __cdecl ShimDbgValFromString(const char* expression)
            {
                if (expression == nullptr)
                    return 0;
                const std::string key = LowerAscii(expression);
                auto& state = GetState();
                if (const auto it = state.expressions.find(key); it != state.expressions.end())
                    return it->second;
                if (const auto it = state.registers.find(key); it != state.registers.end())
                    return it->second;
                return 0;
            }

            bool __cdecl ShimDbgIsValidExpression(const char* expression)
            {
                if (expression == nullptr)
                    return false;
                return GetState().validExpressions.count(LowerAscii(expression)) != 0;
            }

            bool __cdecl ShimDbgValToString(const char* expression, std::uintptr_t value)
            {
                auto& state = GetState();
                if (!state.valToStringResult || expression == nullptr)
                    return false;
                const std::string key = LowerAscii(expression);
                state.registers[key] = value;
                state.validExpressions.insert(key);
                return true;
            }

            bool __cdecl ShimDbgMemRead(std::uintptr_t address, void* destination, std::uintptr_t size)
            {
                auto& state = GetState();
                if (destination == nullptr)
                    return false;
                if (size == 0)
                    return true;
                const auto maximum = std::numeric_limits<std::uintptr_t>::max();
                if (size > maximum - address)
                    return false;
                auto* out = static_cast<unsigned char*>(destination);
                for (std::uintptr_t offset = 0; offset < size; ++offset)
                {
                    const auto it = state.image.find(address + offset);
                    if (it == state.image.end())
                        return false;
                    out[offset] = it->second;
                }
                return true;
            }

            bool __cdecl ShimDbgMemWrite(std::uintptr_t address, const void* source, std::uintptr_t size)
            {
                auto& state = GetState();
                if (!state.memWriteResult || source == nullptr)
                    return false;
                if (size == 0)
                    return true;
                const auto maximum = std::numeric_limits<std::uintptr_t>::max();
                if (size > maximum - address)
                    return false;
                const auto* bytes = static_cast<const unsigned char*>(source);
                for (std::uintptr_t offset = 0; offset < size; ++offset)
                    state.image[address + offset] = bytes[offset];
                return true;
            }

            bool __cdecl ShimDbgMemMap(void* memoryMap)
            {
                auto& state = GetState();
                if (memoryMap == nullptr || !state.memMapResult)
                    return false;
                auto* map = static_cast<BRIDGE_MEMORY_MAP*>(memoryMap);
                map->count = static_cast<int>(state.pages.size());
                map->page = nullptr;
                if (!state.pages.empty())
                {
                    auto* buffer = static_cast<BRIDGE_MEMORY_PAGE*>(
                        std::malloc(sizeof(BRIDGE_MEMORY_PAGE) * state.pages.size()));
                    if (buffer == nullptr)
                        return false;
                    for (std::size_t i = 0; i < state.pages.size(); ++i)
                    {
                        buffer[i].mbi = state.pages[i].mbi;
                        std::memset(buffer[i].info, 0, sizeof(buffer[i].info));
                        strncpy_s(buffer[i].info, state.pages[i].info.c_str(), _TRUNCATE);
                    }
                    map->page = buffer;
                }
                return true;
            }

            std::uintptr_t __cdecl ShimDbgMemFindBaseAddr(std::uintptr_t address, std::uintptr_t* size)
            {
                for (const auto& page : GetState().pages)
                {
                    const auto base = reinterpret_cast<std::uintptr_t>(page.mbi.AllocationBase);
                    const auto regionSize = static_cast<std::uintptr_t>(page.mbi.RegionSize);
                    if (base != 0 && regionSize != 0 && address >= base && address - base < regionSize)
                    {
                        if (size != nullptr)
                            *size = regionSize;
                        return base;
                    }
                }
                if (size != nullptr)
                    *size = 0;
                return 0;
            }

            HANDLE __cdecl ShimDbgGetProcessHandle() { return GetState().processHandle; }

            void __cdecl ShimDbgGetThreadList(void* threadList)
            {
                auto& state = GetState();
                auto* list = static_cast<BRIDGE_THREAD_LIST*>(threadList);
                list->count = static_cast<int>(state.threads.size());
                list->list = nullptr;
                list->currentThread = state.currentThread;
                if (!state.threads.empty())
                {
                    auto* buffer = static_cast<BRIDGE_THREAD_ALL_INFO*>(
                        std::malloc(sizeof(BRIDGE_THREAD_ALL_INFO) * state.threads.size()));
                    if (buffer == nullptr)
                    {
                        list->count = 0;
                        return;
                    }
                    for (std::size_t i = 0; i < state.threads.size(); ++i)
                        buffer[i] = state.threads[i];
                    list->list = buffer;
                }
            }

            void __cdecl ShimBridgeFree(void* buffer) { std::free(buffer); }

            void __cdecl ShimDbgDisasmFastAt(std::uintptr_t address, void* instruction)
            {
                auto& state = GetState();
                auto* info = static_cast<BASIC_INSTRUCTION_INFO*>(instruction);
                std::memset(info, 0, sizeof(*info));
                info->addr = address;
                info->size = state.disasmSize;
                if (!state.disasmText.empty())
                    strncpy_s(info->instruction, state.disasmText.c_str(), _TRUNCATE);
            }

            bool __cdecl ShimDbgGetModuleAt(std::uintptr_t address, char* text)
            {
                if (text == nullptr)
                    return false;
                const std::string name = ModuleNameAt(address);
                if (name.empty())
                    return false;
                CopyCapped(text, name);
                return true;
            }

            bool __cdecl ShimDbgGetLabelAt(std::uintptr_t address, int segment, char* text)
            {
                (void)segment;
                if (text == nullptr)
                    return false;
                const auto it = GetState().labels.find(address);
                if (it == GetState().labels.end())
                    return false;
                CopyCapped(text, it->second);
                return true;
            }

            bool __cdecl ShimDbgGetCommentAt(std::uintptr_t address, char* text)
            {
                if (text == nullptr)
                    return false;
                const auto it = GetState().comments.find(address);
                if (it == GetState().comments.end())
                    return false;
                CopyCapped(text, it->second);
                return true;
            }

            bool __cdecl ShimDbgXrefGet(std::uintptr_t address, XREF_INFO* info)
            {
                if (info == nullptr)
                    return false;
                const auto it = GetState().xrefs.find(address);
                if (it == GetState().xrefs.end())
                    return false;
                // ScanXrefs consumes the records synchronously, so a reused
                // static window is safe and keeps ownership trivially clear.
                static XREF_RECORD window[512];
                const std::size_t count = std::min(it->second.size(), std::size_t{512});
                for (std::size_t i = 0; i < count; ++i)
                {
                    window[i].address = it->second[i].from;
                    window[i].type = it->second[i].type;
                }
                info->refcount = static_cast<std::uintptr_t>(it->second.size());
                info->references = it->second.empty() ? nullptr : window;
                return true;
            }

            std::uintptr_t __cdecl ShimDbgGetXrefCountAt(std::uintptr_t address)
            {
                const auto it = GetState().xrefCounts.find(address);
                return it == GetState().xrefCounts.end() ? 0 : it->second;
            }

            bool EraseBreakpoint(int type, std::uintptr_t address)
            {
                auto& vec = GetState().breakpoints[type];
                const std::size_t before = vec.size();
                vec.erase(
                    std::remove_if(vec.begin(), vec.end(), [address](const State::BpEntry& entry)
                    {
                        return entry.address == address;
                    }),
                    vec.end());
                return vec.size() < before;
            }

            bool __cdecl ShimDbgCmdExecDirect(const char* cmd)
            {
                if (cmd == nullptr)
                    return false;
                auto& state = GetState();
                const std::string command(cmd);
                state.execLog.push_back(command);
                if (!state.execRejectContains.empty() &&
                    command.find(state.execRejectContains) != std::string::npos)
                    return false;
                if (!state.execDirectResult)
                    return false;

                std::uintptr_t address = 0;
                const bool hasAddress = CommandAddress(command, address);
                if (command == "bc" || command == "bphc" || command == "bpmc")
                {
                    const int type = command == "bc" ? 1 : command == "bphc" ? 2 : 4;
                    GetState().breakpoints[type].clear();
                    return true;
                }
                if ((command.starts_with("bc ") || command.starts_with("bphc ") ||
                        command.starts_with("bpmc ")) &&
                    hasAddress)
                {
                    const int type = command.starts_with("bc ") ? 1 : command.starts_with("bphc ") ? 2 : 4;
                    return EraseBreakpoint(type, address);
                }
                if (command.starts_with("bp ") && hasAddress)
                {
                    State::BpEntry entry;
                    entry.address = address;
                    const auto hexEnd = command.find(',', 3);
                    const std::string rest = hexEnd == std::string::npos ? std::string{} : command.substr(hexEnd + 1);
                    std::string token;
                    for (char c : rest + ",")
                    {
                        if (c == ',')
                        {
                            if (token == "ss")
                                entry.singleshoot = true;
                            else if (!token.empty() && entry.name.empty())
                                entry.name = token;
                            token.clear();
                        }
                        else
                            token.push_back(c);
                    }
                    EraseBreakpoint(1, address);
                    GetState().breakpoints[1].push_back(std::move(entry));
                    return true;
                }
                if ((command.starts_with("bph ") || command.starts_with("bpm ")) && hasAddress)
                {
                    State::BpEntry entry;
                    entry.address = address;
                    const int type = command.starts_with("bph ") ? 2 : 4;
                    EraseBreakpoint(type, address);
                    GetState().breakpoints[type].push_back(std::move(entry));
                    return true;
                }
                if (command.starts_with("switchthread ") && hasAddress)
                {
                    for (std::size_t i = 0; i < state.threads.size(); ++i)
                    {
                        if (state.threads[i].basicInfo.threadId == static_cast<DWORD>(address))
                        {
                            state.currentThread = static_cast<int>(i);
                            return true;
                        }
                    }
                    return false;
                }
                return true;
            }

            int __cdecl ShimDbgGetBpList(int type, void* list)
            {
                if (list == nullptr)
                    return 0;
                auto* map = static_cast<NativeBreakpointMap*>(list);
                map->count = 0;
                map->bp = nullptr;
                if (type != 1 && type != 2 && type != 4)
                    return 0;
                const auto it = GetState().breakpoints.find(type);
                const std::size_t count = it == GetState().breakpoints.end() ? 0 : it->second.size();
                if (count == 0)
                    return 0;
                auto* buffer = static_cast<NativeBreakpoint*>(std::calloc(count, sizeof(NativeBreakpoint)));
                if (buffer == nullptr)
                    return -1;
                for (std::size_t i = 0; i < count; ++i)
                {
                    buffer[i].type = type;
                    buffer[i].addr = it->second[i].address;
                    buffer[i].enabled = true;
                    buffer[i].singleshoot = it->second[i].singleshoot;
                    buffer[i].active = true;
                    strncpy_s(buffer[i].name, it->second[i].name.c_str(), _TRUNCATE);
                    strncpy_s(buffer[i].mod, ModuleNameAt(it->second[i].address).c_str(), _TRUNCATE);
                }
                map->count = static_cast<int>(count);
                map->bp = buffer;
                return static_cast<int>(count);
            }
        } // namespace

        void Reset()
        {
            GetState() = State{};
            g_pendingCallRestore = PendingCallRestore{};
            g_lastCallReturn = CallReturnCapture{};
            // N1 pipe auth: no session token outside the auth tests, so the
            // HandleRequest dispatch tests keep their legacy token-free shape.
            g_pipeToken.clear();
            g_rendezvousPathOverride.clear();
            // Invalidate the CollectModuleRecords cache so scripted pages
            // installed after a previous test are always recollected.
            ++g_debuggerGeneration;
        }

        void SetDebugging(bool debugging) { GetState().debugging = debugging; }
        void SetRunning(bool running) { GetState().running = running; }

        void SetRegister(const std::string& name, std::uintptr_t value)
        {
            const std::string key = LowerAscii(name);
            GetState().registers[key] = value;
            GetState().validExpressions.insert(key);
        }

        void SetExpression(const std::string& expression, std::uintptr_t value)
        {
            GetState().expressions[LowerAscii(expression)] = value;
        }

        void SetExpressionValid(const std::string& expression, bool valid)
        {
            const std::string key = LowerAscii(expression);
            if (valid)
                GetState().validExpressions.insert(key);
            else
                GetState().validExpressions.erase(key);
        }

        void SetValToStringResult(bool ok) { GetState().valToStringResult = ok; }
        void SetMemWriteResult(bool ok) { GetState().memWriteResult = ok; }

        void WriteImage(std::uintptr_t address, const void* data, std::size_t size)
        {
            if (data == nullptr || size == 0)
                return;
            const auto* bytes = static_cast<const unsigned char*>(data);
            for (std::size_t i = 0; i < size; ++i)
                GetState().image[address + i] = bytes[i];
        }

        void WriteImageBytes(std::uintptr_t address, const std::vector<unsigned char>& data)
        {
            if (!data.empty())
                WriteImage(address, data.data(), data.size());
        }

        void WriteImageString(std::uintptr_t address, const char* text)
        {
            if (text == nullptr)
                return;
            WriteImage(address, text, std::strlen(text) + 1);
        }

        void WriteImageString16(std::uintptr_t address, const char* asciiText)
        {
            if (asciiText == nullptr)
                return;
            std::vector<unsigned char> bytes;
            for (const char* p = asciiText; *p != '\0'; ++p)
            {
                bytes.push_back(static_cast<unsigned char>(*p));
                bytes.push_back(0);
            }
            bytes.push_back(0);
            bytes.push_back(0);
            WriteImageBytes(address, bytes);
        }

        bool ReadImageByte(std::uintptr_t address, unsigned char& value)
        {
            const auto it = GetState().image.find(address);
            if (it == GetState().image.end())
                return false;
            value = it->second;
            return true;
        }

        void ClearImage() { GetState().image.clear(); }

        FakePage MakeImagePage(std::uintptr_t base, std::size_t size, DWORD protect, const std::string& info)
        {
            FakePage page;
            page.mbi.BaseAddress = reinterpret_cast<PVOID>(base);
            page.mbi.AllocationBase = reinterpret_cast<PVOID>(base);
            page.mbi.RegionSize = static_cast<SIZE_T>(size);
            page.mbi.State = MEM_COMMIT;
            page.mbi.Protect = protect;
            page.mbi.Type = MEM_IMAGE;
            page.info = info;
            return page;
        }

        void SetMemoryPages(std::vector<FakePage> pages) { GetState().pages = std::move(pages); }
        void SetMemMapResult(bool ok) { GetState().memMapResult = ok; }

        void SetModuleName(std::uintptr_t base, const std::string& name)
        {
            GetState().moduleNames[base] = name;
        }

        void SetLabelText(std::uintptr_t address, const std::string& text)
        {
            GetState().labels[address] = text;
        }

        void SetCommentText(std::uintptr_t address, const std::string& text)
        {
            GetState().comments[address] = text;
        }

        void AddBreakpoint(int type, std::uintptr_t address, const std::string& name, bool singleshoot)
        {
            State::BpEntry entry;
            entry.address = address;
            entry.name = name;
            entry.singleshoot = singleshoot;
            GetState().breakpoints[type].push_back(std::move(entry));
        }

        void ClearBreakpoints() { GetState().breakpoints.clear(); }

        BRIDGE_THREAD_ALL_INFO MakeThread(int number, DWORD threadId, std::uintptr_t entry, const std::string& name)
        {
            BRIDGE_THREAD_ALL_INFO info{};
            info.basicInfo.threadNumber = number;
            info.basicInfo.threadId = threadId;
            info.basicInfo.threadStartAddress = entry;
            info.basicInfo.threadLocalBase = entry + 0x1000;
            info.threadCip = entry + 0x10;
            strncpy_s(info.basicInfo.threadName, name.c_str(), _TRUNCATE);
            return info;
        }

        void SetThreads(std::vector<BRIDGE_THREAD_ALL_INFO> threads, int currentThread)
        {
            GetState().threads = std::move(threads);
            GetState().currentThread = currentThread;
        }

        void SetDisasm(const std::string& text, int size)
        {
            GetState().disasmText = text;
            GetState().disasmSize = size;
        }

        void SetXrefCount(std::uintptr_t target, std::uintptr_t count)
        {
            GetState().xrefCounts[target] = count;
        }

        void SetXrefs(std::uintptr_t target, std::vector<FakeXref> refs)
        {
            GetState().xrefs[target] = std::move(refs);
        }

        const std::vector<std::string>& ExecLog() { return GetState().execLog; }
        void ClearExecLog() { GetState().execLog.clear(); }
        void SetExecDirectResult(bool ok) { GetState().execDirectResult = ok; }
        void SetExecRejectContains(const std::string& text) { GetState().execRejectContains = text; }
        void SetProcessHandle(HANDLE handle) { GetState().processHandle = handle; }

        FARPROC LookupBridgeProc(const char* name)
        {
            if (name == nullptr)
                return nullptr;
            const std::string proc(name);
            if (proc == "DbgIsDebugging")
                return reinterpret_cast<FARPROC>(&ShimDbgIsDebugging);
            if (proc == "DbgIsRunning")
                return reinterpret_cast<FARPROC>(&ShimDbgIsRunning);
            if (proc == "DbgValFromString")
                return reinterpret_cast<FARPROC>(&ShimDbgValFromString);
            if (proc == "DbgIsValidExpression")
                return reinterpret_cast<FARPROC>(&ShimDbgIsValidExpression);
            if (proc == "DbgValToString")
                return reinterpret_cast<FARPROC>(&ShimDbgValToString);
            if (proc == "DbgMemRead")
                return reinterpret_cast<FARPROC>(&ShimDbgMemRead);
            if (proc == "DbgMemWrite")
                return reinterpret_cast<FARPROC>(&ShimDbgMemWrite);
            if (proc == "DbgMemMap")
                return reinterpret_cast<FARPROC>(&ShimDbgMemMap);
            if (proc == "DbgMemFindBaseAddr")
                return reinterpret_cast<FARPROC>(&ShimDbgMemFindBaseAddr);
            if (proc == "DbgGetProcessHandle")
                return reinterpret_cast<FARPROC>(&ShimDbgGetProcessHandle);
            if (proc == "DbgGetThreadList")
                return reinterpret_cast<FARPROC>(&ShimDbgGetThreadList);
            if (proc == "BridgeFree")
                return reinterpret_cast<FARPROC>(&ShimBridgeFree);
            if (proc == "DbgDisasmFastAt")
                return reinterpret_cast<FARPROC>(&ShimDbgDisasmFastAt);
            if (proc == "DbgGetModuleAt")
                return reinterpret_cast<FARPROC>(&ShimDbgGetModuleAt);
            if (proc == "DbgGetLabelAt")
                return reinterpret_cast<FARPROC>(&ShimDbgGetLabelAt);
            if (proc == "DbgGetCommentAt")
                return reinterpret_cast<FARPROC>(&ShimDbgGetCommentAt);
            if (proc == "DbgXrefGet")
                return reinterpret_cast<FARPROC>(&ShimDbgXrefGet);
            if (proc == "DbgGetXrefCountAt")
                return reinterpret_cast<FARPROC>(&ShimDbgGetXrefCountAt);
            if (proc == "DbgCmdExecDirect")
                return reinterpret_cast<FARPROC>(&ShimDbgCmdExecDirect);
            if (proc == "DbgGetBpList")
                return reinterpret_cast<FARPROC>(&ShimDbgGetBpList);
            return nullptr;
        }
    } // namespace testshim
} // namespace dbglink

HMODULE WINAPI DbglinkTestShimGetModuleHandleW(LPCWSTR lpModuleName)
{
    if (lpModuleName != nullptr &&
        (_wcsicmp(lpModuleName, L"x64bridge.dll") == 0 || _wcsicmp(lpModuleName, L"x32bridge.dll") == 0))
        return reinterpret_cast<HMODULE>(static_cast<std::uintptr_t>(0xDB6100C1u));
    return GetModuleHandleW(lpModuleName);
}

FARPROC WINAPI DbglinkTestShimGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    if (hModule == reinterpret_cast<HMODULE>(static_cast<std::uintptr_t>(0xDB6100C1u)) &&
        lpProcName != nullptr && reinterpret_cast<std::uintptr_t>(lpProcName) > 0xFFFF)
    {
        if (FARPROC scripted = dbglink::testshim::LookupBridgeProc(lpProcName))
            return scripted;
        return nullptr;
    }
    return GetProcAddress(hModule, lpProcName);
}
