# Admin UI redesign plan (internal/ui)

Status: **implemented (2026-07-13), round two also done, not yet committed**.
Tasks 1-5 below are complete, plus a second pass: shared components extracted
(`toggle-switch`, `panel-header`, `rule-ring-row`, `rule-type-badge`), app.js
split into toast/notify/clipboard/motion.js, logo.svg as favicon + sidebar
brand, more motion (donut/ring sweep-in, sparkline draw, glance-tile stagger,
live-row flash, terminal caret, Bot Shield hover bob; hidden: donut click
replays, shield x5 salutes the nav), challenge page aligned (JSON config tag
fixes the editor error), and the login page — with the user's explicit OK this
round — got restrained hints only (logo wordmark, dark-green buttons, flatter
corners, rise-in). All motion is `prefers-reduced-motion`-guarded.

## What the user asked for (2026-07-13)

- Tired of the current look: "curve curve curve" cards that pop in your face.
- Better text-to-card ratio (text is small relative to big padded cards).
- A proper, coherent color scheme.
- Too much undifferentiated white space; wants real gaps and visible separation
  between blocks ("people should be able to see the difference").
- Do NOT overdo the whole page; restrained, not flashy.
- Remove AI-slop wording wherever touched (avoid-ai-writing skill, edit mode).
- **Do not change the login page — it's perfect as is.**

## Survey findings (why it looks the way it does)

- `base.html` `.card` = `border-radius: 28px` + floating shadow `0 10px 40px` — the main
  "popping" offender. `.btn-primary` is a full pill (`border-radius: 999px`).
- Radius tally across templates: 129× `rounded-full`, 46× `rounded-[10px]`,
  35× `rounded-2xl`, 29× `rounded-xl`, plus `rounded-[28px]`/`[32px]`/`[20px]` one-offs.
- Sidebar is a detached floating rounded-2xl card (`fixed left-4 top-4 bottom-4`),
  body offset `ml-[288px]`.
- Colors (base.html tailwind.config): brand `#76C893`, brand.dark `#2A9D8F` (teal —
  clashes with the green), navy `#2B5C74`, canvas `#EAEBED`, surface `#F4F7F9`,
  line `#E2E5EA` (borders too faint to separate blocks).
- Dashboard hero card has a decorative `blur-2xl` brand blob + photo + gradient.
- `confirm_modal.html` has an "iridescent shimmer" conic-gradient decoration and
  20px radius glassmorphism.
- **login.html is fully standalone** (own `<head>`, own tailwind.config) — base.html
  changes cannot leak into it. Verified.
- JS injects classed HTML too: `static/js/src/app.js` (toast shadow `0 12px 40px`,
  notif badge), `static/js/src/logs.js` (datepicker popover `rounded-[18px]`,
  many `rounded-lg` buttons, `rounded-[8px]/[9px]` inputs). Templates alone are not
  enough — JS must be updated and re-minified via `make generate`.

## Design language decided (flat, tight, differentiated)

- **Radii**: cards 8px (`rounded-lg`), controls/inputs 6px (`rounded-md`), badges 4px
  (`rounded`). Keep `rounded-full` ONLY for: status dots (w-2/w-[5px]/[6px]/[11px]),
  toggle switches in settings.html (a rectangular toggle reads broken), avatars/flag
  circles where genuinely circular.
- **Cards**: white, 1px clearly visible border (≈`#D8DDE3`), shadow either none or
  `0 1px 2px rgba(16,24,40,.04)`. No more floating 40px-blur shadows.
- **Buttons**: rectangular `rounded-md`. Primary button needs a darker green —
  `#76C893` with white text fails contrast (~2:1).
- **Colors**: keep green/navy identity. Change `brand.dark` `#2A9D8F` (teal) → a true
  dark green (~`#2E7D5B`) so text-brand-dark is coherent and passes contrast.
  Page bg (canvas) slightly darker than cards; `line` darker (≈`#D9DEE3`) so borders
  actually separate blocks. Chart hexes in dashboard.min.js (`#76C893`, `#2B5C74`)
  stay as accents — no JS color change needed.
- **Spacing**: main `p-7`→`p-6`, page-header `mb-7`→`mb-6`, dashboard row `gap-6 mb-6`
  →`gap-4 mb-4`, card `p-6`→`p-5`, card-header `py-5`→`py-4`. H1 `text-[28px]`→~22–24px.
- **Differentiation**: card headers get `border-b`; table `thead` gets `bg-surface`;
  kicker labels stay small but consider uppercase tracking. Don't add decoration.

## File-by-file plan (tasks #7–#11 in the task list)

### 1. base.html (task #7)
- tailwind.config color tokens as above.
- `.card`: `border-radius: 10px→8px; border: 1px solid <visible>; box-shadow: none/tiny`.
- `.btn-primary`: dark green bg, `border-radius: 6px`, weight 600.
- Sidebar: attach it — `fixed left-0 top-0 bottom-0`, no rounding, `border-r`;
  body offset `ml-[288px]`→`ml-[264px]`. Nav links `rounded-2xl`→`rounded-md`.
- Page header smaller; notif panel `rounded-2xl` + big shadow → `rounded-lg` + border.

### 2. components/ (task #8)
- `card_header.html`: add `border-b border-line`, `py-5`→`py-4`, badge pill→`rounded`.
- `remove_btn.html`: `rounded-full`→`rounded-md`.
- `empty_state.html`: fine, maybe `p-12`→`p-10`.
- `confirm_modal.html`: drop the iridescent shimmer div, radius 20px→10px,
  buttons 14px→8px radius, tone the glassmorphism down (plain white + border is fine).

### 3. Template sweep, ALL except login.html (task #9)
Files: dashboard, logs, services, settings, ip_rules, geo_rules, waf_rules,
threat_intel, certificates, notifications, log_row.

sed replacements per file (safe re `hgi-rounded` — all patterns include `rounded-` + suffix):
```
rounded-[28px] → rounded-lg      rounded-[32px] → rounded-lg
rounded-[20px] → rounded-lg      rounded-2xl    → rounded-lg
rounded-xl     → rounded-md      rounded-[12px] → rounded-md
rounded-[10px] → rounded-md      rounded-[9px]  → rounded-md
rounded-[6px]  → rounded         rounded-[5px]  → rounded
```
Keep `rounded-[1px]/[2px]/[3px]` (flag corners).

Pill badges → `rounded`: sed -E for `rounded-full (px-)` and
`(px-[^ "]+ py-[^ "]+) rounded-full`, then `grep -n rounded-full` each file and
hand-review the rest. Circle icon buttons (`w-8 h-8 rounded-full`,
`w-9 h-9 rounded-full`, `w-6 h-6 rounded-full` + flex) → `rounded-md`.
**Preserve**: settings.html toggle switches, tiny dots, circular flag avatars.

Manual items:
- dashboard.html: remove the decorative `blur-2xl` blob (line ~18); rightpanel dark
  cards `rounded-[28px]`; Bot Shield card uses absolute positioning tuned to `p-5` —
  don't change its padding; consider `text-[42px]`→36px stats; table zebra rows OK.
- Tables: `thead` row gets `bg-surface`.
- Spacing tightening per the language above (careful, `p-6` appears in non-card spots).

### 4. JS (task #10)
- `static/js/src/app.js`: toast `box-shadow:0 12px 40px…` → flatter (border + small
  shadow); keep notif badge circle.
- `static/js/src/logs.js`: popover `rounded-[18px]`→`rounded-lg`, shadow
  `0 8px 40px`→smaller, inputs `rounded-[8px]`→`rounded-md`, apply btn
  `rounded-[9px]`→`rounded-md`.
- Then `make generate` (never bare `go build` after JS edits) — regenerates
  `static/js/dist/*.min.js`.

### 5. Verify (task #11)
- `go test ./internal/ui/` (template render tests will catch parse errors).
- `make lint` (Go untouched in theory, but generate step touches embed inputs).
- `grep -n 'rounded-2xl\|rounded-\[2\|rounded-\[3\|shadow-\[0_8px\|blur-2xl'` audit.
- AI-slop pass over any prose strings touched (em dashes → plain punctuation; do NOT
  touch `—` empty-cell placeholders like `Score —` or the persisted
  `"Auto-banned — "` / `"Banned via API — "` note prefixes).
- CHANGELOG `[Unreleased]` entry for the restyle.

## Context from earlier in this session (already done, NOT committed)

- TOTP 2FA feature: complete + tested (`internal/security/totp/`,
  `internal/ui/twofactor.go`, settings 2FA card, login two-step — the redesign sweep
  must ALSO restyle the new `twofa-card` in settings.html, but must NOT touch the
  TOTP branch of login.html).
- internal/ui AI-slop cleanup + CHANGELOG 1.4.10 entry: done.
- Nothing in this session has been committed; user hasn't asked for a commit.
