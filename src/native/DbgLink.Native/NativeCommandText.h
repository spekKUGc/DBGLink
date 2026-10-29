#pragma once
#include <cstddef>
#include <string_view>

namespace dbglink
{
    // Character safety plus the byte cap for an argument slot. Callers pass
    // the cap from NativeTypes.h (or the managed schema's maxLength) so the
    // direct pipe endpoint cannot bypass the advertised limits. The command
    // quoting cannot embed a literal quote, and control characters would
    // terminate or corrupt the command line, so both are rejected instead of
    // escaped. Bytes >= 0x80 stay allowed for UTF-8 text.
    inline bool IsQuotedArgumentWithinLimit(std::string_view text, std::size_t maxBytes)
    {
        if (text.size() > maxBytes)
            return false;
        for (unsigned char c : text)
        {
            if (c < 0x20 || c == '"' || c == 0x7F)
                return false;
        }
        return true;
    }

    // SEC J5: DOS device stem (CON/PRN/AUX/NUL/COM1-9/LPT1-9/CONIN$/CONOUT$),
    // case-insensitive. Applied per path component so `C:\dir\con` and
    // `C:\nul.txt` are both rejected: both resolve to devices, not files.
    // Stems are ASCII by construction; any non-ASCII stem is not a device.
    template <typename Char>
    bool IsDosDeviceStem(std::basic_string_view<Char> stem)
    {
        if (stem.size() < 3 || stem.size() > 7)
            return false;
        char upper[8]{};
        for (std::size_t i = 0; i < stem.size(); ++i)
        {
            if (stem[i] > static_cast<Char>(127))
                return false;
            const char narrow = static_cast<char>(stem[i]);
            upper[i] = (narrow >= 'a' && narrow <= 'z')
                ? static_cast<char>(narrow - ('a' - 'A'))
                : narrow;
        }
        const std::string_view name(upper, stem.size());
        if (name == "CON" || name == "PRN" || name == "AUX" || name == "NUL")
            return true;
        if (name.size() == 4 && name[3] >= '1' && name[3] <= '9' &&
            (name.substr(0, 3) == "COM" || name.substr(0, 3) == "LPT"))
            return true;
        if (name == "CONIN$" || name == "CONOUT$")
            return true;
        return false;
    }

    // Shared per-component DOS-device scan used by the drive-path gate below
    // and by wide-char path helpers (IsSafeLocalPath) that cannot use the
    // drive-letter gate. A bare trailing-dot/space component (`con `, `nul.`)
    // still resolves to the device, so it is rejected too.
    template <typename Char>
    bool PathHasDosDeviceComponent(std::basic_string_view<Char> path)
    {
        std::size_t begin = 0;
        while (begin <= path.size())
        {
            std::size_t end = begin;
            while (end < path.size() && path[end] != static_cast<Char>('\\') && path[end] != static_cast<Char>('/'))
                ++end;
            const std::basic_string_view<Char> component(path.data() + begin, end - begin);
            if (!component.empty())
            {
                std::size_t stemEnd = 0;
                while (stemEnd < component.size() && component[stemEnd] != static_cast<Char>('.') &&
                    component[stemEnd] != static_cast<Char>(':') && component[stemEnd] != static_cast<Char>(' '))
                    ++stemEnd;
                if (stemEnd > 0 && IsDosDeviceStem(component.substr(0, stemEnd)))
                    return true;
                if (stemEnd == 0)
                {
                    bool onlyDotsSpaces = true;
                    for (const Char c : component)
                    {
                        if (c != static_cast<Char>('.') && c != static_cast<Char>(' '))
                        {
                            onlyDotsSpaces = false;
                            break;
                        }
                    }
                    if (onlyDotsSpaces)
                        return true;
                }
            }
            if (end == path.size())
                break;
            begin = end + 1;
        }
        return false;
    }

    // SEC J5: local absolute drive path gate for debug-target paths. Requires
    // `X:\...` / `X:/...` and rejects UNC (`\\host\...`), NT device prefixes
    // (`\\?\`, `\\.`) and DOS device components. Forward slashes stay allowed
    // (existing callers/tests use `C:/...`); `arguments` is NOT a path and is
    // intentionally unchecked here. ADS colons (any `:` past the drive colon
    // at index 1) are rejected to mirror managed DbgLinkConfigPath.IsSafePath;
    // any doubled separator (`\\`, `//`, plus mixed `\/`, `/\`) is rejected.
    template <typename Char>
    bool IsLocalAbsoluteDrivePath(std::basic_string_view<Char> path)
    {
        if (path.size() < 3)
            return false;
        const Char drive = path[0];
        const bool driveLetter = (drive >= static_cast<Char>('A') && drive <= static_cast<Char>('Z')) ||
            (drive >= static_cast<Char>('a') && drive <= static_cast<Char>('z'));
        if (!driveLetter || path[1] != static_cast<Char>(':'))
            return false;
        if (path[2] != static_cast<Char>('\\') && path[2] != static_cast<Char>('/'))
            return false;
        // Leading `\\` / `//` (UNC, `\\?\`, `\\.\`) can never follow the drive
        // check above, but reject doubled separators anywhere as defense in
        // depth against `C:\...\UNC`-style smuggling. `?` is rejected outright:
        // it is illegal in Windows paths and only appears in device prefixes
        // (`\\?\`, `\??\`). A second `:` anywhere past the drive colon is an
        // NTFS alternate-data-stream (`file:stream`, `dir:stream\...`) and is
        // rejected to mirror the managed IsSafePath colon rule.
        for (std::size_t i = 0; i < path.size(); ++i)
        {
            if (path[i] == static_cast<Char>(':') && i != 1)
                return false;
            if (path[i] == static_cast<Char>('?'))
                return false;
            if (i + 1 < path.size())
            {
                const Char a = path[i];
                const Char b = path[i + 1];
                const bool aSep = a == static_cast<Char>('\\') || a == static_cast<Char>('/');
                const bool bSep = b == static_cast<Char>('\\') || b == static_cast<Char>('/');
                if (aSep && bSep)
                    return false;
            }
        }
        // Per-component DOS device check shared with IsSafeLocalPath.
        if (PathHasDosDeviceComponent(path))
            return false;
        return true;
    }

    inline bool IsLocalAbsoluteDrivePath(std::string_view path)
    {
        return IsLocalAbsoluteDrivePath<char>(path);
    }

    inline bool IsLocalAbsoluteDrivePath(std::wstring_view path)
    {
        return IsLocalAbsoluteDrivePath<wchar_t>(path);
    }
}
