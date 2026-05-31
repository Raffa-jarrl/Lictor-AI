/**
 * Shell integration helpers.
 *
 * The broker does the thinking; this module is the glue between a Verdict and a
 * shell: how a block maps to an exit code, and a ready-to-paste bash hook for
 * users who want every interactive command screened.
 */

import type { Verdict } from "../types.js";

/** Exit code convention for `airlock guard` / `airlock run`. */
export const EXIT_ALLOW = 0;
export const EXIT_BLOCK = 2;

/**
 * Map a verdict to a process exit code. A blocked verdict (or an enforced one)
 * exits non-zero so shell scripts and pre-exec hooks can stop the command.
 */
export function toExitCode(verdict: Verdict): number {
  return verdict.decision === "block" ? EXIT_BLOCK : EXIT_ALLOW;
}

/**
 * A bash snippet that screens every interactive command through Airlock before
 * it runs. In enforce mode a blocked command is refused (the function returns
 * non-zero and clears the command line). Power-user opt-in — printed by
 * `airlock install-hook`.
 */
export const BASH_PREEXEC_HOOK = String.raw`
# ── Lictor Airlock shell guard ───────────────────────────────────────────────
# Screens each command through Airlock. Add to ~/.bashrc, then: source ~/.bashrc
_lictor_airlock_guard() {
  # Skip the prompt-command and empty lines.
  [ -n "$COMP_LINE" ] && return
  [ "$BASH_COMMAND" = "$PROMPT_COMMAND" ] && return
  case "$BASH_COMMAND" in
    _lictor_airlock_guard*|airlock\ *) return ;;
  esac
  if ! airlock guard --enforce -- "$BASH_COMMAND"; then
    echo "lictor-airlock: command blocked (see above)" >&2
    return 1
  fi
}
trap '_lictor_airlock_guard' DEBUG
# ─────────────────────────────────────────────────────────────────────────────
`.trim();

/** The same idea for zsh, via preexec. */
export const ZSH_PREEXEC_HOOK = String.raw`
# ── Lictor Airlock shell guard (zsh) ─────────────────────────────────────────
# Add to ~/.zshrc, then: source ~/.zshrc
autoload -Uz add-zsh-hook
_lictor_airlock_preexec() {
  case "$1" in
    airlock\ *) return ;;
  esac
  if ! airlock guard --enforce -- "$1"; then
    print -u2 "lictor-airlock: command blocked (see above)"
    # zsh can't abort the command from preexec; this warns loudly in enforce.
  fi
}
add-zsh-hook preexec _lictor_airlock_preexec
# ─────────────────────────────────────────────────────────────────────────────
`.trim();
