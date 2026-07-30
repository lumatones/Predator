# Predator — AGENTS.md

> AI coding rules distilled from Clean Code, Refactoring, A Philosophy of Software Design & Clean Architecture.
> Use `docs/RULES.md` for process/workflow rules. This file governs code quality and design.

---

## 1. Clean Code (everyday coding)

- **Small focused functions** at one level of abstraction. Tell the story top-down: intent before detail.
- **Precise names, one term per concept.** Rename when vocabulary hides intent. No comments that narrate code.
- **Separate commands from queries.** A function that answers must not mutate behind the reader's back.
- **Keep the happy path readable.** Isolate error handling, cleanup, and edge cases.
- **Expose behavior, not raw representation.** Avoid train-wreck access, utility dumping grounds, mixed responsibilities.
- **Keep construction, framework, persistence, and transport OUTSIDE business logic.**
- **Tests are production code.** Readable, deterministic, aligned with the contract they protect.
- **Remove the smell that most increases change cost.** Don't silently broaden the task beyond the smallest cleanup that makes the change safe.
- **When a comment explains control flow → simplify names or structure instead.**
- **When a function mixes setup, validation, computation, and side effects → split the phases.**

## 2. Refactoring (safe restructuring)

- **Preserve observable behavior.** Isolate structural changes from behavior changes. Never disguise a redesign as cleanup.
- **Work in small, reversible, buildable, testable steps.** Split a patch when it's too large to reason about locally.
- **Safety net before risky refactoring.** Characterization tests for unclear behavior. Never delete a failing test to finish cleanup.
- **Refactor the current blocking smell, not every smell.** Duplication, long functions, long parameter lists, feature envy, primitive obsession, repeated conditionals.
- **Make names and functions reveal intent.** Rename before deeper work when bad names block understanding.
- **Stop when the requested change is easy, the smell is gone, and the next cleanup would be speculative.**
- **When the same edit appears for a third time → remove duplication through clearer ownership.**
- **When a function mixes responsibilities or abstraction levels → rename, extract, split phases before adding more logic.**
- **When one change forces edits across many files → centralize the knowledge or introduce a clearer boundary.**

## 3. Deep Modules (Philosophy of Software Design)

- **Prefer deep modules:** small, semantic interfaces that hide meaningful internal complexity.
- **Design interfaces around what callers need to know**, not how the implementation works. No fragile setup sequences, mode flags, or exposed internal choices.
- **Hide volatile decisions** inside the module that owns the knowledge: storage shape, protocols, file formats, performance hacks, bookkeeping.
- **Pull complexity downward.** A slightly more complex implementation is worth it if callers get a simpler contract.
- **Combine or split by total complexity**, not by size, habit, or aesthetics. Keep related state, behavior, invariants together.
- **Use comments for interface contracts, invariants, rationale, and tricky implementation facts.** Do not narrate code.
- **When a feature feels awkward or one change spreads across files → look for missing information hiding, shallow modules, or complexity pushed to callers.**
- **When adding a layer, wrapper, or abstraction → prove it hides more complexity than it adds.**

## 4. Clean Architecture (boundaries)

- **Source dependencies must point inward.** Domain and use cases must not import frameworks, databases, web handlers, ORM rows, or UI types.
- **Inner layers own the interfaces they need; outer layers implement them.** Wire concrete dependencies at the composition root.
- **Adapters translate, don't decide.** Controllers, endpoints, gateways, and presenters convert external formats to use-case calls and back.
- **Organize by use case / feature / business capability** before generic technical buckets (controllers, services, utils).
- **Test entities, use cases, and boundary contracts without the real framework, database, or network.** Test adapters separately at the seams.
- **When framework types, ORM rows, or vendor SDKs enter core policy → move translation outward.**
- **When a use case instantiates infrastructure directly → introduce a policy-owned port, wire the concrete detail at the edge.**
- **Compromises stay at the outermost layer.** Document the violation, don't normalize it, preserve a path to separation.

---

## Quick Heuristics

| Smell | Action |
|-------|--------|
| Function > 30 lines | Extract until each tells a single story |
| Comment explains what code does | Rename or restructure, then remove comment |
| Function both returns AND mutates | Split into query + command |
| Same edit in 3+ places | Centralize through ownership, not copying |
| Feature requires changes across 5+ files | Introduce boundary or hide knowledge |
| Framework types in business logic | Add adapter, move translation outward |
| New abstraction/wrapper added | Verify it hides complexity, not just adds a name |
