#include <windows.h>

// Stable export names let Ghidra find the same evidence with or without a PDB.
extern "C"
{
    __declspec(dllexport) const wchar_t* FixtureUnicodePointer = L"DBGLink \u041f\u0440\u0438\u0432\u0435\u0442 \u4e2d\U0001F600";
    __declspec(dllexport) __declspec(noinline) DWORD FixtureImportedPid()
    {
        return GetCurrentProcessId();
    }
    __declspec(dllexport) __declspec(noinline) int FixtureCallee(int value)
    {
        return value * 3 + 7;
    }
    __declspec(dllexport) __declspec(noinline) int FixtureCaller(int value)
    {
        return FixtureCallee(value) + static_cast<int>(FixtureUnicodePointer[0]);
    }
}

int main()
{
    return FixtureCaller(5) == 90 ? 0 : 1;
}
