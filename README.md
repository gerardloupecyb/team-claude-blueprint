# Team Claude Blueprint

A standardized, reusable workflow kit for Claude Code projects. Clone this repo, run setup, and every team member gets the same tools, conventions, and workflow.

## Prerequisites

- [Claude Code](https://docs.claude.com/en/docs/claude-code) installed
- Git installed
- A [Supermemory](https://supermemory.ai) account (for Tier 3 memory)

## Quick Start

### 1. Clone this repo

```bash
git clone https://github.com/YOUR-ORG/team-claude-blueprint.git
cd team-claude-blueprint
```

### 2. Run setup

```bash
chmod +x setup.sh
./setup.sh
```

This installs:
- **specification-architect** skill (evidence-based architecture docs)
- **DevOps skills** (Terraform, Kubernetes, CI/CD, monitoring)
- **CARL hook** (context management)

### 3. Start a new project

```bash
mkdir ~/projects/my-new-project
cd ~/projects/my-new-project
git init

# Copy the workflow template
cp /path/to/team-claude-blueprint/CLAUDE.md.template ./CLAUDE.md

# Copy CARL context management
cp -r /path/to/team-claude-blueprint/.carl ./.carl

# Start Claude Code
claude
```

### 4. Follow the workflow

Inside Claude Code:
```
/gsd:new-project
```

Then follow the 9-phase lifecycle defined in your CLAUDE.md.

## What's Included

### Skills (installed globally by setup.sh)

| Skill | Purpose |
|---|---|
| `specification-architect` | Evidence-based architecture docs (6-phase) |
| `iac-terraform` | Terraform/Terragrunt infrastructure as code |
| `k8s-troubleshooter` | Kubernetes diagnostics and incident response |
| `ci-cd` | Pipeline design across platforms |
| `gitops-workflows` | ArgoCD, Flux CD deployment patterns |
| `monitoring-observability` | Metrics, alerts, SLOs |
| `aws-cost-optimization` | FinOps and cost analysis |

### Pre-installed (no setup needed)

| Tool | Purpose |
|---|---|
| **GSD** | Project management, roadmap, phased execution |
| **compound-engineering** | Autonomous workflows, code reviews, swarm execution |

### Memory & Context System (3-tier)

| Tier | Tool | Survives reset? | Scope |
|---|---|---|---|
| 1 (Hot) | MEMORY.md | Yes | Per-project, always in prompt |
| 2 (Warm) | CARL | Yes | Per-project, injected per prompt |
| 3 (Cold) | Supermemory | Yes | Cross-project, cloud-based |

### Workflow Template (CLAUDE.md)

The 9-phase lifecycle:

1. **Project Setup** (GSD) -> PROJECT.md, ROADMAP.md
2. **Architecture** (specification-architect) -> research, blueprint, design, tasks
3. **Plan Validation** (compound-engineering) -> multi-agent review
4. **Execution Planning** (GSD) -> PLAN.md files
5. **Building** (GSD or compound-engineering swarm)
6. **Testing** (unit + integration + E2E with Playwright)
7. **Code Review** (compound-engineering + security/performance agents)
8. **Verification** (GSD) -> UAT against success criteria
9. **DevOps** (Terraform, CI/CD, monitoring when applicable)

## File Reference

| File | Purpose | Copy to |
|---|---|---|
| `CLAUDE.md.template` | Project workflow template | Project root as `CLAUDE.md` |
| `.carl/manifest` | CARL domain registry | Project root as `.carl/manifest` |
| `.carl/context` | Context bracket rules | Project root as `.carl/context` |
| `.carl/global` | Global coding rules | Project root as `.carl/global` |
| `carl-hook.py` | CARL hook script | `~/.claude/hooks/carl-hook.py` |
| `setup.sh` | Global installer | Run once per machine |
| `skill-sources.md` | Skill repo links | Reference only |
| `mcp-config.md` | Supermemory MCP setup | Reference only |

## Team Onboarding Checklist

- [ ] Clone this repo
- [ ] Run `setup.sh`
- [ ] Set up Supermemory MCP (see `mcp-config.md`)
- [ ] Create first project with `/gsd:new-project`
- [ ] Verify CARL is active (look for `<carl-rules>` in responses)
- [ ] Verify skills load (check `/help` for available skills)

## Updating

Pull the latest from this repo and re-run `setup.sh` to update skills and configurations.

## License

MIT
