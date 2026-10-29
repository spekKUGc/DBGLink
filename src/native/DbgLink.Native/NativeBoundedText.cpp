#include "NativeTypes.h"
#include "NativeBoundedText.h"

namespace dbglink
{
    BoundedText::BoundedText(std::size_t limit, OverflowPolicy policy)
        : limit_(limit), policy_(policy)
    {
    }

    void BoundedText::Assign(std::string_view text)
    {
        text_.assign(text.data(), text.size());
    }

    const std::string& BoundedText::Body() const noexcept
    {
        return text_;
    }

    bool BoundedText::Truncated() const noexcept
    {
        return truncated_;
    }

    bool BoundedText::Fits(std::size_t charCount) const noexcept
    {
        // Overflow-guarded form of text_.size() + charCount <= limit_ (the
        // shape the inspection/trace formatters already used).
        return charCount <= limit_ - std::min(limit_, text_.size());
    }

    bool BoundedText::Append(std::string_view text)
    {
        if (policy_ == OverflowPolicy::Latch && truncated_)
            return false;
        if (!Fits(text.size()))
        {
            truncated_ = true;
            return false;
        }
        text_.append(text.data(), text.size());
        return true;
    }

    bool BoundedText::AppendLine(std::string_view line)
    {
        if (policy_ == OverflowPolicy::Latch && truncated_)
            return false;
        if (!Fits(line.size() + 1))
        {
            truncated_ = true;
            return false;
        }
        text_.push_back('\n');
        text_.append(line.data(), line.size());
        return true;
    }

    void BoundedText::AppendFlag(const char* name, bool enabled)
    {
        if (enabled)
            Append("\n" + std::string(name) + "=true");
    }

    void BoundedText::AppendMarker(std::string_view marker)
    {
        if (truncated_)
            text_.append(marker.data(), marker.size());
    }

    void BoundedText::AppendMarker(std::string_view marker, std::size_t headroom)
    {
        if (truncated_ && Fits(headroom))
            text_.append(marker.data(), marker.size());
    }

    void BoundedText::PopTrailingNewline() noexcept
    {
        if (!text_.empty() && text_.back() == '\n')
            text_.pop_back();
    }
}
