#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    // Shared bounded reply-body builder for the text formatters (module,
    // thread, call-stack, disassembly, search, inspection and trace replies).
    // Each site previously grew its own copy of the same pattern: stop
    // appending once the body would exceed a character budget, record that
    // truncation, and append an "outputTruncated=true" (or
    // "addressOverflow=true") marker that still fits. The fit arithmetic and
    // the latch live here; callers keep their exact marker strings, headroom
    // checks and limits so the wire text stays byte-identical.
    class BoundedText
    {
    public:
        enum class OverflowPolicy
        {
            // A miss returns false and later appends may still fit; used by
            // the list loops that break and write their own marker.
            Report,
            // The first miss latches Truncated() and drops every later
            // append; used by the flag-tail search/inspection/trace replies.
            Latch,
        };

        BoundedText(std::size_t limit, OverflowPolicy policy);

        // Replaces the body without a budget check. Only the reply headers
        // use it: they were built with a plain assignment before the budget
        // loop and are far smaller than any limit.
        void Assign(std::string_view text);

        const std::string& Body() const noexcept;
        bool Truncated() const noexcept;

        // Fit-checked append: false leaves the body unchanged and records the
        // miss (which latches further appends under OverflowPolicy::Latch).
        bool Append(std::string_view text);

        // Fit-checked append of '\n' plus line, counting the prefix in the
        // budget (the "\n"-separated inspection/trace/call-stack shape).
        bool AppendLine(std::string_view line);

        // Fit-checked "\nname=true" tail flag, appended only when enabled.
        void AppendFlag(const char* name, bool enabled);

        // Truncation marker: written only after a recorded miss. The headroom
        // overload keeps the caller's original "size + headroom <= limit"
        // room check; the plain overload is for the replies that reserve
        // budget (-32/-40) so the marker always fits.
        void AppendMarker(std::string_view marker);
        void AppendMarker(std::string_view marker, std::size_t headroom);

        // Drops one trailing '\n' when present (the shared list tail).
        void PopTrailingNewline() noexcept;

    private:
        bool Fits(std::size_t charCount) const noexcept;

        std::string text_;
        std::size_t limit_ = 0;
        OverflowPolicy policy_ = OverflowPolicy::Report;
        bool truncated_ = false;
    };
}
