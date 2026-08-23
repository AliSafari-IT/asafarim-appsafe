# @asafarim/shared-tokens

Local workspace package that ships the AppSafe design tokens as a single CSS custom-property stylesheet. Consumed by `apps/web` and `apps/demo`.

## Usage

Import once at the root of your application:

```ts
import "@asafarim/shared-tokens/styles.css";
```

Then reference the variables in your own CSS — no hard-coded colors, spacing, radii, typography, shadows, or transitions.

```css
.card {
  background: var(--color-surface);
  color: var(--color-ink);
  border: var(--border-width) solid var(--color-border);
  border-radius: var(--radius-lg);
  padding: var(--space-5);
  box-shadow: var(--shadow-card);
  font-family: var(--font-sans);
  transition: transform var(--transition-normal);
}
```

## Token catalog

All tokens are defined on `:root` in [`styles.css`](./styles.css).

### Color

| Token | Value |
| --- | --- |
| `--color-ink-strong` | `#f7f8ff` |
| `--color-ink` | `#c6cce0` |
| `--color-ink-muted` | `#8992ad` |
| `--color-ink-inverse` | `#10131d` |
| `--color-bg` | `#090b12` |
| `--color-bg-elevated` | `#10131d` |
| `--color-surface` | `#151a27` |
| `--color-surface-raised` | `#1b2232` |
| `--color-surface-soft` | `#111827` |
| `--color-border` | `#273149` |
| `--color-border-strong` | `#3a496a` |
| `--color-accent` | `#92a7ff` |
| `--color-accent-strong` | `#738cff` |
| `--color-accent-soft` | `#1b2750` |
| `--color-success` | `#85d8b1` |
| `--color-success-soft` | `#15382f` |
| `--color-danger` | `#ff9eaa` |
| `--color-danger-soft` | `#41212d` |
| `--color-warning` | `#f4c77d` |
| `--color-focus` | `#c2ceff` |

### Spacing

`--space-0` `0` · `--space-1` `0.25rem` · `--space-2` `0.5rem` · `--space-3` `0.75rem` · `--space-4` `1rem` · `--space-5` `1.25rem` · `--space-6` `1.5rem` · `--space-7` `1.75rem` · `--space-8` `2rem` · `--space-10` `2.5rem` · `--space-12` `3rem` · `--space-16` `4rem` · `--space-20` `5rem` · `--space-24` `6rem`

### Radius

`--radius-sm` `0.5rem` · `--radius-md` `0.875rem` · `--radius-lg` `1.25rem` · `--radius-xl` `1.75rem` · `--radius-pill` `999rem`

### Typography

| Token | Value |
| --- | --- |
| `--font-sans` | Inter, ui-sans-serif, system-ui, ... |
| `--font-mono` | SFMono-Regular, Consolas, Liberation Mono, monospace |
| `--text-xs` | `0.75rem` |
| `--text-sm` | `0.875rem` |
| `--text-md` | `1rem` |
| `--text-lg` | `1.125rem` |
| `--text-xl` | `1.375rem` |
| `--text-section` | `clamp(1.75rem, 4vw, 3rem)` |
| `--text-2xl` | `clamp(2.5rem, 7vw, 5.75rem)` |
| `--leading-tight` | `1.05` |
| `--leading-snug` | `1.25` |
| `--leading-normal` | `1.6` |
| `--weight-regular` | `400` |
| `--weight-medium` | `500` |
| `--weight-semibold` | `600` |
| `--weight-bold` | `700` |
| `--tracking-tight` | `-0.02em` |
| `--tracking-wide` | `0.08em` |

### Shadow

`--shadow-card` · `--shadow-glow` · `--shadow-focus` · `--shadow-signal`

### Motion

`--transition-fast` `160ms ease` · `--transition-normal` `240ms ease`

### Layout

`--content-max` `78rem` · `--control-height` `3rem` · `--border-width` `1px` · `--opacity-muted` `0.72`

## License

MIT.
