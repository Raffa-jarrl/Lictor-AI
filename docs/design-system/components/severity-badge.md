# Component: SeverityBadge

> **Status:** Spec drafted 2026-05-15. Not yet implemented anywhere.
> **First consumer:** Lictor Studio (Tauri) finding-list renderer.
> **Second consumer:** Mission Control public transparency pages (post-launch).
> **Token dependencies:** `--accent`, `--critical`, `--warning`, `--success`, `--text-muted`, plus the matching `-tint` variants and `--radius-pill`.

---

## Description

A small, pill-shaped indicator that labels a security finding (or system event) with one of five severity levels. Used everywhere Lictor surfaces audit results — Studio, Mission Control, the marketing site's transparency reports, the launch teardown blog posts, and the docs.

The badge **always pairs with text** describing what's at that severity level — it is never decorative alone. A badge with no accompanying text is a bug.

---

## Levels

Mirrors the exact 5-tier language used in `skills/lictor-security-check/SKILL.md` so designers, agents, and humans share a single vocabulary.

| Variant | Token bg | Token text | Emoji prefix | Label | Plain-English meaning |
|---|---|---|---|---|---|
| `critical` | `--critical-tint` | `--critical` | 🔴 | **CRITICAL** | Someone can hurt you with this today. Don't ship until fixed. |
| `high` | `--warning-tint` | `--warning` | 🟠 | **HIGH** | Bad day waiting to happen. Fix this week. |
| `medium` | `--accent-tint` | `--accent` | 🟡 | **MEDIUM** | Worth fixing. Add to the queue. |
| `low` | `--info-tint` | `--text-muted` | 🔵 | **LOW** | Nice-to-have. Backlog. |
| `info` | `--info-tint` | `--text-muted` | ⚪ | **INFO** | Just letting you know. |

(`medium` and `accent` share a color — that's intentional. Yellow is the Lictor brand color; medium severity is the "default" tier where most findings land, so it inherits the brand accent rather than getting a unique color.)

---

## Visual

```
┌─ critical ──────────────────────┐
│  🔴 CRITICAL                     │  <- bg: --critical-tint
│                                  │     text: --critical, weight 600
└──────────────────────────────────┘     border-radius: --radius-pill
                                          padding: --space-1 --space-3
                                          font: JetBrains Mono, 0.7rem, letter-spacing 0.1em
```

The emoji prefix is part of the badge's render. Don't render the emoji separately as decoration — it lives inside the pill so screen readers announce it correctly and so the badge is self-contained when copy-pasted to GitHub, Slack, an email.

---

## API

### Markdown (canonical for `SECURITY-AUDIT.md`)

Already in use. Keep it.

```markdown
🔴 **CRITICAL** · `path/to/file.ts:42`
🟠 **HIGH** · `path/to/file.ts:128`
🟡 **MEDIUM** · `path/to/file.ts:201`
🔵 **LOW** · `path/to/file.ts:340`
⚪ **INFO** · `notes`
```

The `·` separator is a middle dot (U+00B7), not a hyphen. Don't substitute.

### HTML / CSS (for Studio + Mission Control + transparency pages)

```html
<span class="severity-badge severity-badge--critical" role="img" aria-label="Critical severity">
  🔴 CRITICAL
</span>
```

CSS (target file: a new `landing/components.css` once we have ≥2 components, otherwise inline in the consuming page):

```css
.severity-badge {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  padding: var(--space-1) var(--space-3);
  border-radius: var(--radius-pill);
  font-family: "JetBrains Mono", monospace;
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  white-space: nowrap;
  user-select: none;
}
.severity-badge--critical { background: var(--critical-tint); color: var(--critical); }
.severity-badge--high     { background: var(--warning-tint);  color: var(--warning);  }
.severity-badge--medium   { background: var(--accent-tint);   color: var(--accent);   }
.severity-badge--low      { background: var(--info-tint);     color: var(--text-muted); }
.severity-badge--info     { background: var(--info-tint);     color: var(--text-muted); }
```

### Solid (Studio frontend)

```tsx
type Severity = "critical" | "high" | "medium" | "low" | "info";

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "🔴 Critical",
  high:     "🟠 High",
  medium:   "🟡 Medium",
  low:      "🔵 Low",
  info:     "⚪ Info",
};

export function SeverityBadge(props: { level: Severity }) {
  return (
    <span
      class={`severity-badge severity-badge--${props.level}`}
      role="img"
      aria-label={`${props.level} severity`}
    >
      {SEVERITY_LABEL[props.level]}
    </span>
  );
}
```

---

## States

| State | Visual | Behavior |
|---|---|---|
| Default | Tint background, severity-color text, all-caps label | None — badge is non-interactive |
| Hover | Same | Cursor stays default (`cursor: default`). The badge is a label, not a button. |
| Focused (if inside a focusable parent) | Inherit parent's focus ring | Don't add a separate focus ring on the badge itself |
| Disabled | N/A — a finding's severity isn't a toggleable state | If you need to "dim" a resolved finding, dim the whole `FindingCard`, not the badge |

---

## Accessibility

- `role="img"` and `aria-label="<level> severity"` are mandatory. The emoji alone is not a reliable announcement across screen readers.
- The label text inside is uppercase via CSS (`text-transform`), not via the source string. Keep the source as "Critical" / "High" / etc. — screen readers read "C R I T I C A L" if you write the source in caps.
- Color is decorative; the text label carries the meaning. Never rely on the badge color alone (this is also why the emoji prefix is non-negotiable).
- Contrast: each `tint` background paired with its sibling foreground passes WCAG AA at 4.5:1 against `--bg`. Recheck if you ever modify the tints — the 0.10–0.14 alpha values are deliberately at the contrast floor.

---

## Do / Don't

| ✅ Do | ❌ Don't |
|---|---|
| Pair with descriptive text immediately after (`🔴 CRITICAL · Path traversal in /api/docs`) | Show the badge alone with no context |
| Use exactly one badge per finding | Stack multiple badges (Severity AND Category AND Status) — that's a different component (TBD: `FindingChips`) |
| Match the Markdown rendering byte-for-byte across surfaces | Invent new severity levels like "blocker" or "deferred" — those are statuses, not severities |
| Keep the emoji inside the badge element | Render the emoji outside and the label inside |
| Render in JetBrains Mono | Render in Inter or Cormorant — the monospace is the "this is a system label" signal |

---

## Open questions

- **Does Studio's high-DPI desktop render need a different padding scale?** Probably not, but verify when implementing.
- **Should there be a "compact" variant** (no label, emoji only) for dense lists? Defer until we have a list dense enough to need it. Premature.
- **Localization:** the labels (Critical / High / etc.) are English. Translator agent should decide whether to translate them or leave them as English-jargon (the way developers leave `Error` and `Warning` in English in non-EN UIs). Lean: leave in English; the emoji prefix carries the meaning.

---

## Related

- [`docs/design-system/README.md`](../README.md) — tokens this component depends on
- `skills/lictor-security-check/SKILL.md` — the 5-tier severity vocabulary this badge renders
- `studio/src/components/` (when implemented) — the first Solid implementation
