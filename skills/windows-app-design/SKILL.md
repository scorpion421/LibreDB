---
name: windows-app-design
description: >-
  Native Microsoft Windows Fluent 2 app design and best-practices standard for WinUI 3, WPF, egui,
  Tauri, and desktop GUIs. Enforces authentic Microsoft Learn typography, semantic tokens, Light/Dark
  luminance layering, Contrast theme compliance, DPI scaling, keyboard accessibility, and zero
  AI-slop styling.
---

# Native Windows Fluent 2 app design standard

Grounds every Windows or desktop GUI in official Microsoft Learn specifications:
- App design overview: https://learn.microsoft.com/en-us/windows/apps/design/guidelines-overview
- Windows app best practices: https://learn.microsoft.com/en-us/windows/apps/get-started/best-practices

## 1. Anti-AI-slop prohibitions

Never ship generic LLM dashboard styling on Windows:
- **Zero neon or multi-hue gradients**: Do not use purple/indigo/cyan/magenta glow gradients on backgrounds, cards, headers, or primary buttons.
- **Zero pill-heavy oversized geometry**: Never use `>= 16px` card/button corner radii, floating glassmorphism blobs, or glowing box shadows.
- **Zero heavy typographic weights**: Do not mark every heading or metric with `Bold (700+)` or uppercase all-caps tracking badges everywhere.
- **Zero gratuitous decoration**: Omit synthetic sparklines, circular gauges, bouncy springs, or busy animations where crisp native Fluent controls belong.
- **Zero blocking modal nags**: Never freeze the window with repetitive confirmation popups; surface non-blocking inline banners, `InfoBar` notices, or status text.

## 2. Typography (`Segoe UI Variable`)

Use `Segoe UI Variable` (`Display`, `Text`, `Small` optical masters) on Windows (or platform equivalent fallback on cross-platform targets) with **Regular (`400`)** and **Semibold (`600`)** weights only. Avoid `Bold (700+)` and italics in standard chrome, and use sentence case for titles, labels, and navigation items.

| Token | Size / Line height (`epx`) | Weight | Usage |
| :--- | :--- | :--- | :--- |
| `Caption` | `12 / 16` | Regular (`400`) | Captions, footnotes, secondary timestamps |
| `Body` | `14 / 20` | Regular (`400`) | Primary prose, table cells, form labels |
| `Body Strong` | `14 / 20` | Semibold (`600`) | Card titles, field group labels, emphasis |
| `Body Large` | `18 / 24` | Regular (`400`) | Featured list leads or summary lines |
| `Subtitle` | `20 / 28` | Semibold (`600`) | Section headings, sub-view titles |
| `Title` | `28 / 36` | Semibold (`600`) | Primary page header |
| `Title Large` | `40 / 52` | Semibold (`600`) | Top-level hero header when needed |
| `Display` | `68 / 92` | Semibold (`600`) | Rare standalone numeric/launch focal point |

Keep body lines concise (`<= 65-75` characters in text panes) and preserve monospace (`Cascadia Mono` / `Consolas`) strictly for IP endpoints, cryptographic keys, paths, and log lines.

## 3. Shape, corner radii, and spacing (`4px` grid)

- **Semantic corner radii**:
  - `OverlayCornerRadius` (`8px`): App panels, cards, dialogs, menus, and content containers.
  - `ControlCornerRadius` (`4px`): Standard buttons, text boxes, combo boxes, list rows, tab pills, and toggles (track keeps classic rounded capsule strictly matching standard Windows toggle switches).
  - Micro accents (`2px`): Active selection indicator pill, inline progress track, hairline scrollbars.
- **Spacing rhythm**: Strict `4px` base grid (`4px`, `8px`, `12px`, `16px`, `20px`, `24px`). Keep interactive hit targets at least `32px` height (`40px` recommended for mixed touch/pointer controls) with minimum `4px-8px` clearance between adjacent buttons.
- **Surface separation**: Separate cards and chrome with `1px` crisp hairline borders (`CardStrokeColorDefault` / `ControlStrokeColorDefault`) and subtle step luminance rather than thick opaque dividers or heavy blur shadows.

## 4. Semantic colors, luminance layering, and materials

Model depth via luminance elevation tiers rather than hue shifts:

| Semantic role | Light mode guidance | Dark mode guidance |
| :--- | :--- | :--- |
| App canvas (`SolidBackgroundFillColorBase` / `Mica`) | Cool neutral (`#F3F3F3`) | Deep charcoal neutral (`#202020`) |
| Layer / card surface (`LayerFillColorDefault` / `CardBackgroundFillColorDefault`) | Elevated clean white (`#FFFFFF` / `rgba(255,255,255,0.70)`) | Subtle lifted slate (`#2C2C2C` / `rgba(255,255,255,0.05)`) |
| Interactive control (`ControlFillColorDefault`) | Tinted white (`#FFFFFF` subtle alpha) | Raised slate (`rgba(255,255,255,0.06)`) |
| Control hover / pressed | Step up/down alpha (`ControlFillColorSecondary` / `Tertiary`) | Subtle highlight (`rgba(255,255,255,0.08)` / `0.04`) |
| Border stroke (`CardStrokeColorDefault` / `ControlStrokeColorDefault`) | `1px` hairline (`rgba(0,0,0,0.08)` / `0.06`) | `1px` top-edge bevel highlight (`rgba(255,255,255,0.08)`) |
| Primary / secondary text (`TextFillColorPrimary` / `Secondary`) | `#1A1A1A` (`0.90`) / `#5C5C5C` (`0.61`) | `#FFFFFF` (`1.0`) / `#CFCFCF` (`0.78`) |
| Single system accent (`AccentFillColorDefault`) | Windows system accent (`#005FB8` default) | Accessible lightened accent (`#60CDFF` default) |
| Semantic status (`SystemFillColorSuccess`/`Caution`/`Critical`) | Muted accessible green/amber/red with badge icon | High-contrast pastel pill / icon pairing |

Material discipline:
- Apply **Mica** or **Mica Alt** strictly to the persistent top-level window frame or navigation pane background so desktop wallpaper subtly tints neutral chrome.
- Apply **Acrylic** strictly to transient lightweight overlays (`MenuFlyout`, `TeachingTip`, popovers), never to stacked inner cards.
- Reserve `AccentFillColorDefault` + `TextOnAccentFillColorPrimary` exclusively for the primary action on a view, active toggles, and the active nav indicator bar. Secondary buttons remain neutral (`ControlFillColorDefault`).

## 5. Contrast, DPI, keyboard, and framework mapping

- **Contrast and themes**: Enforce `>= 4.5:1` contrast ratio for normal text and `>= 3.0:1` for large text (`>= 18px` / `14px` semibold) and focus outlines. Respect Windows Light/Dark switching and Windows Contrast Themes (never hardcode colors when system theme brushes exist). Never encode status with color alone; always pair an icon or text state label.
- **DPI and localization**: Express sizes in effective pixels (`epx`) so controls stay crisp from `100%` (`96 DPI`) through `250%+`. Keep text containers fluid so localized strings expanding by `+30-40%` never clip or wrap awkwardly.
- **Keyboard and accessibility**: Guarantee full `Tab`/`Shift+Tab` ordering, `Arrow` navigation inside sidebars/lists/tabs, `Enter`/`Space` activation, and `Escape` closure with visible dual-ring focus strokes (`FocusStrokeColorOuter` + `FocusStrokeColorInner`). Attach UI Automation accessible names, roles, and live-region updates to every interactive element and status indicator.
- **Immediate responsiveness**: Run network/OS service operations off the UI thread (`async`/worker channel) and reflect instant optimistic or indeterminate progress state (`ProgressRing` / `ProgressBar`).
- **Toolkit mapping (`egui`/`eframe`, `WinUI 3`, `WPF`, `Tauri`)**:
  - `WinUI 3`: Use built-in `NavigationView`, `InfoBar`, `SettingsCard`, `ThemeResource` tokens, `StaticResource` `BodyTextBlockStyle` / `SubtitleTextBlockStyle`, and `SystemBackdrop = MicaBackdrop`.
  - `WPF`: Opt into Fluent theme (`ThemeMode="System"` on .NET 9+ or `WPF-UI`) instead of custom chrome hacks.
  - `egui` / `eframe`: Explicitly map `Visuals::widgets` (`noninteractive`, `inactive`, `hovered`, `active`, `open`) to neutral Fluent luminance steps, set `Rounding::same(8.0)` on windows/frames and `4.0` on widgets, load `segoeui.ttf` / `segoeuib.ttf` if available, keep `stroke` width `1.0`, use Windows Accent (`HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM\AccentColor` or default `#0078D4`/`#60CDFF`) only on `selection.bg_fill` and primary CTA buttons, and avoid modifying non-field methods (e.g. `Visuals::weak_text_color()` is a method, not a field, in `egui 0.29`).
