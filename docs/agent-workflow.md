# Two-Agent Research / Verify Workflow

A disciplined pattern for using AI agents in this lab **without shipping
overclaimed findings**. It exists because the failure mode of a single
autonomous agent is confident, plausible, wrong — a finding that reads well,
cites real code, and collapses the moment a human (or a program's triager)
actually checks it. The fix is an adversarial second agent whose only job is to
try to break the first one's claims.

This is a methodology, not a tool. It was validated on a real engagement where
the reviewer caught the investigator overstating impact (claiming a clipboard /
command-execution chain before it was actually proven, and leaving a
scope-eligibility question unchecked) *before* anything was submitted.

## The two roles

### 1. Investigator
Locates the vulnerable code or behavior and builds a **working** proof of
concept.

- Never source-reading inference alone. If the claim is "X happens," the
  investigator must have run something and observed X.
- Produces: the exact commands, the exact output, the affected file/line, and a
  reproducible PoC artifact.
- Separates, explicitly, what was *proven by execution* from what is *theory*.

### 2. Independent reviewer
Does **not** trust the investigator's transcript. Starts from skepticism.

- Re-reads the relevant code itself.
- Re-runs the load-bearing PoC steps independently; if a result differs, says so
  rather than papering over it.
- Searches the web for prior art: is this a known/duplicate issue? Is the CWE
  right? What severity do comparable accepted reports actually get?
- Grades the finding and gives a blunt verdict: **submit / submit-with-changes /
  don't-submit**, with reasoning for both sides of the eligibility call.

## Non-negotiable rules the workflow enforces

1. **Every claim is backed by something executed and observed** — exact commands
   and output, not a paraphrase of what "should" happen.
2. **Severity is never inflated beyond what was proven.** A benign PoC payload
   (e.g. a marker file) is fine; claiming the *impact ceiling* requires either
   proving it or explicitly labeling it unproven.
3. **The reviewer signs off before anything is submitted.** No finding goes to a
   program on the investigator's confidence alone.
4. **Honest "did not prove" section is mandatory** in any report — it is what
   makes a triager trust the parts you did prove.
5. **Scope first, always.** Both agents operate behind `scripts/scope_guard.py`;
   neither touches a target not authorized in `programs/`.

## Why a separate reviewer and not "just double-check"

A single agent re-reviewing its own work inherits its own blind spots and its
own prior conclusion. A second agent, told explicitly to *disprove* the first,
with its own fresh read of the code and its own web research, catches the
specific class of error that matters most here: a finding that is internally
consistent but doesn't survive contact with reality or with the program's
actual eligibility bar.

## Reference frameworks

These informed the pattern (inspiration, not dependencies — this lab implements
the workflow directly, not by vendoring any of them):

- [usestrix/strix](https://github.com/usestrix/strix)
- [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon)
- [0xSteph/pentest-ai-agents](https://github.com/0xSteph/pentest-ai-agents)
- [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi)
- [BitterSecurity/Decepticon](https://github.com/BitterSecurity/Decepticon)

See also [`ai-assisted-code-review.md`](ai-assisted-code-review.md) for the
file-by-file coverage discipline that feeds the investigator role.
