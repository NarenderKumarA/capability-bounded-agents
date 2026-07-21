# Capability-Bounded Agents

**Provable, injection-resistant action limits for autonomous LLM agents.**

*If prompt injection is provably unfixable inside the model (Abdelnabi & Bagdasarian, 2026),
safety cannot depend on the model. This repo proves a containment property that doesn't:
0% bypass, invariant under adversarial context, for any model.*

## Thesis (falsifiable)
Prompt-based guardrails are *unsound*: their safety depends on the model resisting
injection, so their bypass rate is a function of model robustness and is **never zero**.
An out-of-model **reference monitor** that mediates every tool call against a declared
**capability contract** gives **provable containment (0% bypass) for bounded actions,
regardless of what the model emits** — because the enforcement decision is independent
of the model's prompt and output.

Formally, for any bounded action `a`:
`a executes  ⟹  a is permitted by the contract`, so the contrapositive
(`a not permitted ⟹ a never executes`) holds for **all** model outputs — containment is
invariant under adversarial context.

## What is proven here (today)
`python3 -m cba.harness` runs the containment benchmark: the same attack suite against the
same agent under prompt-guardrail vs. reference-monitor enforcement.

| model | enforcement | bypass rate |
|---|---|---|
| vulnerable-7b | prompt guardrail | 100% |
| vulnerable-7b | **reference monitor** | **0%** |
| hardened-frontier | prompt guardrail | 50% |
| hardened-frontier | **reference monitor** | **0%** |

This proves the **containment half**: whenever an injection flips the model, the monitor
still blocks the bounded action → 0% executed, for every model and attack.

## Real-model empirical eval → separate repo
The mocked table above uses an asserted flip threshold, not a measured one. The real-model
adversarial eval that measures actual bypass rates against live Bedrock Claude models lives
in a companion repo: **[capability-bounded-agents-eval](https://github.com/NarenderKumarA/capability-bounded-agents-eval)**
— it depends on this repo's `cba` package (installed via pip/git) and reuses `ATTACKS`,
`World`, `make_tools`, `CapabilityContract`, and `ReferenceMonitor` unchanged. First result:
both claude-haiku-4-5 and claude-sonnet-4-5 resisted 100% of realistic injections (0%
prompt-mode bypass across 24 real trials) — see that repo for the full table, raw transcripts,
and honest interpretation.

## Why now (related work, as of Jul 2026)
- **Abdelnabi & Bagdasarian, "AI Agents May Always Fall for Prompt Injections" (arXiv, May 2026)**
  prove a formal impossibility result: in-model defenses cannot eliminate prompt injection
  without also breaking legitimate agentic behavior. This work is the direct constructive
  answer — if the model can never be made to resist injection, safety must not depend on it
  resisting injection. The reference monitor's soundness proof holds *regardless of whether
  the model was flipped*, which is precisely what an impossibility result at the model layer
  demands of any real fix.
- **CAIS 2026** (ACM's first agentic-systems security track) hosted a zero-trust proposal
  arguing authorization should move "closer to each operation" — directionally aligned, but
  stops at the architecture sketch. This repo differs by (a) giving a formal soundness
  argument (contrapositive containment proof), not just an architecture, and (b) shipping a
  runnable adversarial benchmark comparing prompt-guardrail vs. monitor enforcement head to
  head.
- **Real-world stakes, not hypothetical**: Microsoft disclosed CVE-2026-25592 /
  CVE-2026-26030 (Semantic Kernel, May 2026) — prompt injection escalating to host-level RCE.
  OWASP still ranks prompt injection #1 in the LLM Top 10. DeepMind's own "Agent Safety
  Post-Training" and "Autonomous Security" reqs describe this exact problem: surface-level
  output filtering/refusal tuning is explicitly called out as insufficient for agents that
  plan and act over long horizons.

## Roadmap
1. ✅ Reference-monitor + capability contract + containment benchmark (this repo).
2. ✅ Real-model adversarial eval — see
   [capability-bounded-agents-eval](https://github.com/NarenderKumarA/capability-bounded-agents-eval):
   0% prompt-mode bypass observed at this injection strength, monitor 0% confirmed
   empirically. Escalating adversary strength to find a real non-zero prompt-mode bypass is
   the immediate follow-up there.
3. ⬜ Expand the attack suite (stronger/obfuscated/multi-turn injections, tool chaining, a
   weaker or less-aligned model e.g. local Ollama, to find a real prompt-mode flip and show
   the monitor still holds it at 0%).
4. ⬜ Formal soundness write-up + threat model.
5. ⬜ arXiv preprint + this repo as the artifact + a demo (injected agent tries `rm -rf`,
   monitor stops it cold).

Target venues: NeurIPS/ICLR safety & agents tracks; USENIX Security / IEEE S&P for the
security framing; agent-safety workshops for fast signal.

## Layout
- `cba/monitor.py` — `CapabilityContract` + `ReferenceMonitor` (the formal object).
- `cba/harness.py` — tools, agent, attack suite, containment benchmark.

## Run
```bash
python3 -m cba.harness
```

## Install (as a dependency)
```bash
pip install "capability-bounded-agents @ git+https://github.com/NarenderKumarA/capability-bounded-agents.git"
```
