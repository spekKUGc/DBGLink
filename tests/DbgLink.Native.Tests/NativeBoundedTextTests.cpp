#include <stdexcept>
#include <string>
#include <string_view>

#include "../../src/native/DbgLink.Native/NativeBoundedText.h"
#include "../../src/native/DbgLink.Native/NativeTypes.h"

namespace dbglink_bounded_text_tests
{
    using namespace dbglink;
    using Policy = BoundedText::OverflowPolicy;

    void Require(bool condition, std::string_view message)
    {
        if (!condition)
            throw std::runtime_error(std::string(message));
    }

    void RunBoundedTextTests()
    {
        // Report policy: a miss is reported, later appends may still fit.
        {
            BoundedText body(10, Policy::Report);
            Require(body.Append("12345"), "fitting append was rejected");
            Require(!body.Append("12345678901"), "over-limit append was accepted");
            Require(body.Body() == "12345", "rejected append changed the body");
            Require(body.Truncated(), "miss was not recorded in Report mode");
            Require(body.Append("67890"), "later fitting append was dropped in Report mode");
            Require(body.Body() == "1234567890", "Report-mode append order was wrong");
        }

        // Latch policy: the first miss drops every later append.
        {
            BoundedText body(10, Policy::Latch);
            Require(body.Append("1234"), "latched append was rejected");
            Require(!body.Append("12345678901"), "over-limit latched append was accepted");
            Require(body.Truncated(), "latched miss was not recorded");
            Require(!body.Append("5"), "append after the latch was not dropped");
            Require(body.Body() == "1234", "latched body changed after the miss");
        }

        // AppendLine counts its '\n' prefix against the budget.
        {
            BoundedText body(5, Policy::Report);
            Require(body.AppendLine("abcd"), "prefixed line within budget was rejected");
            Require(body.Body() == "\nabcd", "AppendLine did not prefix a newline");
            Require(!body.Append("e"), "budget ignored the prefixed newline");
        }

        // Flags append "\nname=true" only when enabled.
        {
            BoundedText body(64, Policy::Report);
            body.AppendFlag("scanTruncated", false);
            Require(body.Body().empty(), "disabled flag was appended");
            body.AppendFlag("scanTruncated", true);
            Require(body.Body() == "\nscanTruncated=true", "flag text drifted");
        }

        // Markers need a recorded miss; the headroom variant also keeps the
        // original "size + headroom <= limit" room check.
        {
            BoundedText body(40, Policy::Report);
            body.AppendMarker("early", 1);
            Require(body.Body().empty(), "marker was written without a miss");
            Require(body.Append(std::string(20, 'a')), "setup append failed");
            Require(!body.Append(std::string(30, 'b')), "over-limit append was accepted");
            body.AppendMarker("X", 21);
            Require(body.Body().size() == 20, "marker exceeded its headroom");
            body.AppendMarker("Y", 20);
            Require(body.Body() == std::string(20, 'a') + "Y", "headroom marker was not written");
        }

        // The plain marker overload is reserve-backed: it appends past the
        // limit (the -32/-40 replies rely on their reserved budget).
        {
            BoundedText body(10, Policy::Latch);
            Require(body.Append("1234567890"), "exact-fit append was rejected");
            Require(!body.Append("x"), "append past the limit was accepted");
            body.AppendMarker("\noutputTruncated=true");
            Require(body.Body() == "1234567890\noutputTruncated=true",
                "reserve-backed marker was not written");
        }

        // Trailing-newline pop and the unbounded header assign.
        {
            BoundedText body(10, Policy::Report);
            body.Assign("line\n");
            body.PopTrailingNewline();
            Require(body.Body() == "line", "trailing newline was not dropped");
            body.Assign("line");
            body.PopTrailingNewline();
            Require(body.Body() == "line", "newline pop touched other text");
            body.Assign("");
            body.PopTrailingNewline();
            Require(body.Body().empty(), "pop on an empty body failed");

            BoundedText header(4, Policy::Latch);
            header.Assign(std::string(40, 'h'));
            Require(header.Body().size() == 40, "header assign was bounded");
        }
    }
}
