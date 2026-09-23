# AGENTS.md

Guidance for AI coding agents (opencode, Claude Code, etc.) working in this repository.

> See `.claude/CLAUDE.md` for the original project guidance (architecture,
> conventions, security, do/don't). This file holds agent-specific process rules.

## GitHub issue conventions

- **Every newly created GitHub issue MUST include an `## Acceptance criteria` section.
- Follow the standardized format: a `## Acceptance criteria` header followed by a
  checkbox list of numbered, verifiable criteria:

```markdown
## Acceptance criteria

- [ ] **AC1:** <verifiable, user/CI-observable outcome>
- [ ] **AC2:** <verifiable, user/CI-observable outcome>
```

- Criteria must be testable/observable (never "done when" prose) — see the merged
  issue templates and the standardized issues (#20, #34, #35, #47, #58, #63, #64,
  #71, #72) for reference.
- Do NOT skip ACs for sub-issues created under an epic.
