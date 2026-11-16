---
name: linux-desktop-hig-design
description: >-
  Native Linux desktop HIG standard covering GNOME Libadwaita/GTK4 and KDE Kirigami/Breeze/Qt6.
  Enforces semantic theme tokens, Adwaita and Kirigami structural components, Noto/Adwaita
  typography, consistent spacing units, XDG desktop portal dark-mode/accent integration, Wayland
  scaling, AT-SPI2 accessibility, and zero AI-slop styling.
---

# Native Linux desktop HIG standard (GNOME Libadwaita and KDE Kirigami)

Grounds every Linux desktop GUI (`GTK4`/`Libadwaita`, `Qt6`/`Kirigami`/`Widgets`, or native cross-toolkit ports) in official GNOME and KDE Human Interface Guidelines:
- KDE Human Interface Guidelines: https://develop.kde.org/hig/
- GNOME Human Interface Guidelines: https://developer.gnome.org/hig/
- GNOME Design Principles: https://developer.gnome.org/hig/principles.html

## 1. Anti-AI-slop prohibitions on Linux desktops

Never treat Linux desktop UIs as unstyled HTML wrappers or glowing dark-theme mockups:
- **Zero hardcoded hex themes ignoring desktop palette**: Never hardcode dark neon backgrounds or force custom colors that break user Breeze/Adwaita Light, Dark, and High Contrast themes or system accent preferences.
- **Zero bloated double headerbars or detached menubar clutter**: Do not stack a native window frame on top of another custom gradient title bar (`CSD` + SSD mismatch) or cram unnecessary ribbons where a clean `HeaderBar` / `ToolBar` belongs.
- **Zero excessive padding or floating pill bloat**: Respect desktop pointer-first compactness (`6px` control radii on GNOME, `4-6px` crisp radii on KDE) rather than `24px` mobile-style blobs and `48px` bloated desktop tiles.
- **Zero emoji or custom multicolor bitmap chrome**: Use platform-matched monochrome symbolic icons (`-symbolic` / `Breeze` SVG masks colored dynamically by foreground ink) for UI controls and toolbar actions.
- **Zero modal nag dialogs**: Surface transient feedback with `AdwToast` or `Kirigami.InlineMessage`, and never freeze all windows with repetitive confirmation popups.

## 2. GNOME HIG (`Libadwaita` / `GTK4` and Design Principles)

Follow GNOME HIG core principles (`Give Content Priority`, `Progressive Disclosure`, `Clear Hierarchy`, `Predictable Conventions`):
- **Window chrome (`AdwToolbarView` + `AdwHeaderBar`)**: Flatten top and bottom chrome (`flat` style over `AdwToolbarView`, avoiding heavy header borders when scrolling uses subtle `undershoot` separation). Place primary view switchers or window titles centrally in `AdwHeaderBar`, keep destructive/overflow menus inside a trailing `GtkMenuButton` (`Primary Menu`), and keep window drag handles generous.
- **Adaptive responsive layouts (`AdwNavigationSplitView` + `AdwBreakpoint`)**: Pair a subtle shaded sidebar (`AdwNavigationPage`, `.navigation-sidebar`) with the main content page, collapsing smoothly at narrow widths (`~600sp`) via `AdwBreakpoint` without horizontal scrollbars.
- **Boxed lists and preferences (`AdwPreferencesGroup` / `.boxed-list`)**: Present structured settings and cards as grouped `.boxed-list` containers (`12px` outer card radius, `6px` internal button/row radius, `1px` crisp `@borders` hairline) using semantic row widgets: `AdwActionRow`, `AdwSwitchRow`, `AdwComboRow`, `AdwSpinRow`, and `AdwEntryRow`.
- **Feedback, empty states, and dialogs**: Use `AdwToastOverlay` for undoable transient confirmations, `AdwStatusPage` (`icon-name`, `title`, `description`, CTA) for clean initial/empty views, `AdwBanner` for persistent non-blocking warnings, and `AdwAlertDialog` strictly for unavoidable binary choices with `.suggested-action` or `.destructive-action` pills and `Escape` cancellation.

## 3. GNOME typography, semantic CSS colors, and spacing

Use GNOME system sans (`Adwaita Sans` / `Cantarell`) and monospace (`Adwaita Mono` / `Source Code Pro`) paired with built-in Libadwaita CSS classes and semantic color variables managed via `AdwStyleManager`:

| Element | GNOME class / semantic token | Guidance |
| :--- | :--- | :--- |
| Hierarchy styles | `.title-1`..`.title-4`, `.heading`, `.body`, `.caption`, `.caption-heading`, `.numeric` | Always use `.numeric` (`tabular-nums`) for aligned counters, sizes, and timers |
| Surfaces & borders | `@window_bg_color`, `@view_bg_color`, `@card_bg_color`, `@headerbar_bg_color`, `@borders` | Never hardcode `#ffffff`/`#1e1e1e`; automatically supports Dark & High Contrast |
| Single system accent | `@accent_bg_color` / `@accent_fg_color` / `@accent_color` | Follows user GNOME 47+ / XDG Portal system accent automatically |
| Semantic status | `@success_color`, `@warning_color`, `@error_color` + `.suggested-action`, `.destructive-action` | Pair color with icon (`-symbolic`) and descriptive text |
| Spacing scale | `6px` (tight related), `12px` (group/row inner), `18px` (standard box margin), `24px` (section gap), `36px` (hero) | Align content measure around `<= 600px` clamped width (`AdwClamp`) |
| Controls & icons | `34px-38px` default desktop button height, `16px` (`-symbolic`) icon inside buttons | Sentence case (`Title Case` ONLY inside `AdwHeaderBar` / `Window` titles if standard, sentence case for labels/rows/menus) |

## 4. KDE HIG (`Kirigami` / `Breeze` / `Qt6` architecture)

Follow KDE's guiding motto **"Simple by default, powerful when needed"**: clean defaults immediately usable by everyone, with advanced power options progressively disclosed via expandable sections, sidebars, or configuration views:
- **Kirigami application shell**: Use `Kirigami.ApplicationWindow` with `globalDrawer` (only for multi-page navigation when >= 3 pages exist; avoid hidden hamburger menus on simple tools), `Kirigami.ScrollablePage` / `Kirigami.PageRow` multi-column navigation (`columnWidth: Kirigami.Units.gridUnit * 20`), and clean page `actions` rendered as native toolbar buttons with automatic overflow into a menu.
- **Forms and cards**: Build settings and structured forms with `Kirigami.FormLayout` (aligning labels right on desktop and collapsing left-aligned above fields on narrow screens; synchronize column alignment across groups with `twinFormLayouts`). Use `Kirigami.AbstractCard` / `Kirigami.Card` sparingly (`4-6px` radius, `1px` hairline border, zero fake blur dropshadows) rather than putting every single item in a nested card.
- **Non-blocking feedback & empty states**: Use `Kirigami.InlineMessage` (`type: Information | Positive | Warning | Error`) inside page layouts, `showPassiveNotification(...)` for fleeting completions, and `Kirigami.PlaceholderMessage` (`icon.name`, `text`, `helpfulAction`) when a list/view is empty.
- **Qt Widgets fallback**: Use `QMainWindow` + standard `QToolBar` / `QStatusBar` / `QDialogButtonBox` + `KMessageWidget` cleanly so system `Breeze` `QStyle` draws native frames, hover highlights, and checkboxes without CSS overrides breaking QStyle metrics.

## 5. KDE Breeze semantic palette, `Units`, Wayland, and portals

Never hardcode colors, pixel dimensions, or fixed DPI metrics in KDE/Qt apps:
- **Semantic palette (`Kirigami.Theme` / `KColorScheme`)**: Bind `colorSet: Kirigami.Theme.Window | View | Button | Header | Tooltip` and read `backgroundColor`, `alternateBackgroundColor`, `textColor`, `disabledTextColor`, `highlightColor` (Breeze default `#3DAEE9`), `positiveTextColor`, `neutralTextColor`, `negativeTextColor`, and `focusColor` strictly from `Kirigami.Theme` / `QPalette` (`KColorScheme`), setting `Kirigami.Theme.inherit: false` explicitly per distinct color set region.
- **Typography and `Kirigami.Units`**: Rely on system `Noto Sans` (`10pt` desktop default) and `Hack` (`monospace`), and scale spacing with `Kirigami.Units` (`smallSpacing = 4px`, `mediumSpacing = 6px`, `largeSpacing = 8px`, `gridUnit = 18px`, `iconSizes.small = 16`, `iconSizes.smallMedium = 22`, `iconSizes.medium = 32`). Use `Qt.fontMetrics` / `Layout.*` instead of fixed widths.
- **Linux platform integration & accessibility**: Integrate `org.freedesktop.portal.Settings` (`color-scheme` and `accent-color`), use Wayland logical pixels + native fractional scaling + keyboard `Shortcut`/`Keys` + visible `activeFocus` indicators (`>= 4.5:1` contrast, `AT-SPI2` `Accessible.name` / `Accessible.description` / `role` on every custom element).
