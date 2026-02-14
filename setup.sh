#!/bin/bash
# Team Claude Blueprint - Setup Script
# Installs all global skills, CARL hook, and prints MCP config instructions.
#
# Usage: ./setup.sh

set -e

echo "=================================="
echo " Team Claude Blueprint - Setup"
echo "=================================="
echo ""

# Ensure ~/.claude directories exist
mkdir -p ~/.claude/skills
mkdir -p ~/.claude/hooks

# ============================================================================
# 1. Install specification-architect skill
# ============================================================================
echo "[1/4] Installing specification-architect skill..."
if [ -d ~/.claude/skills/specification-architect ]; then
  echo "  Already installed. Skipping."
else
  git clone --depth 1 https://github.com/adrianpuiu/specification-document-generator.git /tmp/spec-arch 2>/dev/null
  if [ -d /tmp/spec-arch/specification-architect ]; then
    cp -r /tmp/spec-arch/specification-architect ~/.claude/skills/specification-architect
    echo "  Installed specification-architect."
  else
    echo "  WARNING: Could not find specification-architect in repo."
  fi
  rm -rf /tmp/spec-arch
fi

# ============================================================================
# 2. Install DevOps skills from ahmedasmar/devops-claude-skills
# ============================================================================
echo "[2/4] Installing DevOps skills..."
git clone --depth 1 https://github.com/ahmedasmar/devops-claude-skills.git /tmp/devops-skills 2>/dev/null || true

DEVOPS_SKILLS="iac-terraform k8s-troubleshooter ci-cd gitops-workflows monitoring-observability aws-cost-optimization"
for skill in $DEVOPS_SKILLS; do
  if [ -d ~/.claude/skills/$skill ]; then
    echo "  $skill: already installed."
  elif [ -d "/tmp/devops-skills/$skill" ]; then
    cp -r "/tmp/devops-skills/$skill" ~/.claude/skills/$skill
    echo "  $skill: installed."
  else
    echo "  $skill: not found in repo, skipping."
  fi
done
rm -rf /tmp/devops-skills

# Install lgbarn/devops-skills (Terraform-focused)
echo "  Installing lgbarn/devops-skills..."
if [ -d ~/.claude/plugins/devops-skills ]; then
  echo "  lgbarn devops-skills: already installed."
else
  git clone --depth 1 https://github.com/lgbarn/devops-skills.git /tmp/lgbarn-devops 2>/dev/null || true
  if [ -d /tmp/lgbarn-devops ]; then
    mkdir -p ~/.claude/plugins
    cp -r /tmp/lgbarn-devops ~/.claude/plugins/devops-skills
    echo "  lgbarn devops-skills: installed."
  fi
  rm -rf /tmp/lgbarn-devops
fi

# ============================================================================
# 3. Install CARL hook
# ============================================================================
echo "[3/4] Installing CARL hook..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f ~/.claude/hooks/carl-hook.py ]; then
  echo "  CARL hook already exists. Skipping (update manually if needed)."
else
  if [ -f "$SCRIPT_DIR/carl-hook.py" ]; then
    cp "$SCRIPT_DIR/carl-hook.py" ~/.claude/hooks/carl-hook.py
    echo "  CARL hook installed at ~/.claude/hooks/carl-hook.py"
    echo "  NOTE: You need to register this hook in ~/.claude/settings.json"
    echo "  See the CARL documentation for hook registration instructions."
  else
    echo "  WARNING: carl-hook.py not found in blueprint repo."
  fi
fi

# ============================================================================
# 4. Summary and next steps
# ============================================================================
echo ""
echo "[4/4] Setup complete!"
echo ""
echo "=================================="
echo " Installed Skills"
echo "=================================="
echo ""
ls ~/.claude/skills/ 2>/dev/null | while read skill; do
  echo "  - $skill"
done
echo ""
echo "=================================="
echo " Next Steps"
echo "=================================="
echo ""
echo "1. Set up Supermemory MCP (see mcp-config.md)"
echo ""
echo "2. For each new project:"
echo "   cp $SCRIPT_DIR/CLAUDE.md.template ./CLAUDE.md"
echo "   cp -r $SCRIPT_DIR/.carl ./.carl"
echo ""
echo "3. Start Claude Code and run: /gsd:new-project"
echo ""
echo "4. Restart Claude Code to activate new skills."
echo ""
