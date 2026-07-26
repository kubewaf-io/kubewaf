# AGENTS.md — kubeWAF Project Rules for AI Coding Assistants

This file makes the kubeWAF repository work excellently with **any** AI coding assistant that supports project-level instructions (Cursor, Claude Code, Grok, Continue.dev, Aider, Windsurf, GitHub Copilot, etc.).

When you are helping a developer inside this repository, follow the rules below.

---

## Primary Goal

Help users create **correct, effective, and reviewable** Web Application Firewall rules using kubeWAF's Kubernetes-native model.

---

## When Working With SecRules (the most important rule)

**If the user asks you to create, modify, review, or convert any security rule (SecRule, WAF rule, virtual patch, detection rule, block something, etc.), you MUST:**

1. **Read the expert instructions first**
   - Load and follow: `docs/ai/kubewaf-secrule-expert.md`
   - This file contains the authoritative guidance, golden rules, constant lists, and output style for this project.

2. **Stay accurate — never hallucinate**
   - Only use variable names, operators, action types, and transformations that are actually defined in the code under `api/seclang/v1beta1/`.
   - When unsure, read the real definitions from:
     - `api/seclang/v1beta1/secrule_variables.go`
     - `api/seclang/v1beta1/secrule_operator.go`
     - `api/seclang/v1beta1/secrule_actions.go`
   - Prefer reading the source over memory.

3. **Default to anomaly scoring + `pass`**
   - Custom user rules should almost always contribute to anomaly scores rather than immediately deny (unless the user explicitly requests a hard block).

4. **Use high rule IDs**
   - All custom rules must use IDs **> 100000**.

5. **Offer both formats**
   - Show a clean **raw SecLang** version (what security engineers usually write).
   - Show the equivalent **structured `kind: SecRule`** Kubernetes resource (what goes into Git and the cluster).

6. **Validate output**
   - After generating a `SecRule` YAML, the user (or you) should run:
     ```bash
     kubectl apply -f the-file.yaml --dry-run=server
     ```
   - Or use the conversion tooling in `cmd/crs-converter`.

---

## General Project Conventions

- The project uses a **structured CRD representation** of ModSecurity SecLang rules (enforced by **modsecurity-proxy-wasm**) instead of raw `.conf` files for better validation, reviewability, and GitOps.
- Existing high-quality examples live in `config/samples/crs/`.
- Human documentation for writing rules is in `website/content/docs/operator/writing-rules.mdx` (and legacy `docs/operator/writing-rules.md`) and `docs/reference/seclang-structure.md`.
- The conversion between raw SecLang and the Kubernetes form is implemented in Go (`api/seclang/v1beta1/convert/` and the crs-converter tool).

---

## How to Use the AI Expert Effectively

Tell the AI:

> "Create a SecRule that ..."  
> "I need a virtual patch for ..."  
> "Convert this raw rule to kubeWAF YAML ..."  
> "Review this SecRule I wrote ..."

The assistant will automatically load the expert instructions and produce high-quality, valid output.

For the best possible results, also give the AI access to:
- `docs/ai/kubewaf-secrule-expert.md` (master portable prompt)
- The Go type definitions (for exact constant names)

---

## Other Notes

- This `AGENTS.md` is the single source of truth for AI behavior in this repo.
- The same knowledge is also packaged as a native Grok skill at `.grok/skills/kubewaf-secrule/SKILL.md`.
- Improvements to the expert instructions should be made in `docs/ai/kubewaf-secrule-expert.md`.

---

**Thank you for helping make kubeWAF's security rule authoring experience excellent across every AI tool.**
