//! Built-in native platform UI design skills (`--profile personal`).
//!
//! Grounds generated desktop and mobile interfaces in official platform guidelines:
//! - Windows Fluent 2: https://learn.microsoft.com/en-us/windows/apps/design/guidelines-overview
//!   and https://learn.microsoft.com/en-us/windows/apps/get-started/best-practices
//! - Android UI & Mobile: https://developer.android.com/design/ui/
//!   and https://developer.android.com/design/ui/mobile
//! - Apple HIG (iOS & macOS): https://developer.apple.com/design/human-interface-guidelines,
//!   https://developer.apple.com/design/human-interface-guidelines/designing-for-ios,
//!   and https://developer.apple.com/design/human-interface-guidelines/designing-for-macos
//! - Linux Desktop (KDE & GNOME HIG): https://develop.kde.org/hig/,
//!   https://developer.gnome.org/hig/, and https://developer.gnome.org/hig/principles.html

pub const WINDOWS_APP_DESIGN_SKILL: &str = r##"---
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
"##;

pub const ANDROID_APP_DESIGN_SKILL: &str = r##"---
name: android-app-design
description: >-
  Native Android Material 3 UI and mobile design standard for Jetpack Compose, Android Views, and
  Kotlin Multiplatform apps. Enforces dynamic color and tonal surfaces, Roboto Flex typography in sp,
  edge-to-edge WindowInsets, 48dp touch targets, adaptive Window Size Classes, predictive back, and
  zero AI-slop styling.
---

# Native Android Material 3 UI and mobile design standard

Grounds every Android phone, tablet, foldable, or ChromeOS GUI in official Android Developers guidance:
- Android UI design overview: https://developer.android.com/design/ui/
- Designing for mobile & Material 3: https://developer.android.com/design/ui/mobile

## 1. Anti-AI-slop prohibitions on Android

Never ship generic LLM dashboard cards or hardcoded iOS/web copies on Android:
- **Zero synthetic neon gradients**: Do not paint backgrounds, `Scaffold` headers, or buttons with glowing purple/cyan gradients or fake dark-glass blur blobs. Use Material 3 tonal surface steps instead of drop shadows and gradients.
- **Zero blocked system bars**: Never leave an opaque black/colored box behind the status bar or navigation bar, and never overlap clickable content with cutouts or gesture bars. Always use edge-to-edge with `WindowInsets`.
- **Zero hardcoded static palette overrides**: Never hardcode `#FFFFFF` or `#000000` for containers/text or bypass `MaterialTheme.colorScheme` / `dynamicLightColorScheme` / `dynamicDarkColorScheme` unless strict brand tokens are supplied via a proper `ColorScheme`.
- **Zero cramped touch targets or arbitrary radii**: Never shrink clickable icons below `48dp x 48dp` or pick random corner radii outside the M3 `Shapes` scale.
- **Zero stacked legacy dialogs**: Prefer `ModalBottomSheet`, inline `Snackbar` with action, or non-blocking banners over stacked blocking `AlertDialog` confirmations.

## 2. Typography (`Roboto` / `Roboto Flex` in `sp`)

Use Material 3 `Typography` tokens in scalable pixels (`sp`) so Android's nonlinear font scaling (up to `200%` accessibility scaling) preserves hierarchy without breaking layouts. Express all layout dimensions, spacing, and heights in density-independent pixels (`dp`). Use sentence case for labels, navigation items, buttons, and notifications.

| Token | Size / Line height (`sp`) | Weight / Tracking | Usage |
| :--- | :--- | :--- | :--- |
| `DisplayLarge / Medium / Small` | `57/64`, `45/52`, `36/44` | Regular (`400`) | Hero numerals or short focal headlines |
| `HeadlineLarge / Medium / Small` | `32/40`, `28/36`, `24/32` | Regular (`400`) | Top-level section intros and empty states |
| `TitleLarge` | `22/28` | Regular (`400`) | `TopAppBar` titles, dialog headers |
| `TitleMedium / Small` | `16/24`, `14/20` | Medium (`500`), `+0.15`/`+0.1` | Card headers, list section titles, tabs |
| `BodyLarge / Medium` | `16/24`, `14/20` | Regular (`400`) | Primary copy, list subtitles, form text |
| `BodySmall` | `12/16` | Regular (`400`) | Helper text, timestamps, secondary metadata |
| `LabelLarge / Medium / Small` | `14/20`, `12/16`, `11/16` | Medium (`500`) | Buttons (`LabelLarge`), chips, `NavigationBar` labels |

Keep line lengths readable (`<= 60` characters per line in wide windows using `widthIn(max = 640.dp)`), use monospace only for diagnostic codes, keys, and endpoints, and never use all-caps buttons (M3 buttons use sentence case).

## 3. Dynamic color, tonal surface roles, and M3 shape scale

Represent surface elevation via **tonal surface containers** rather than heavy gray elevation shadows:

| M3 color role | Usage |
| :--- | :--- |
| `primary` / `onPrimary` | Single high-emphasis action (`FloatingActionButton`, filled CTA button, active selection) |
| `primaryContainer` / `onPrimaryContainer` | Active navigation pill indicator, `ExtendedFloatingActionButton`, tonal emphasis |
| `secondaryContainer` / `onSecondaryContainer` | Selected filter chips, secondary tonal buttons, active rail/bar pill |
| `surface` / `onSurface` / `onSurfaceVariant` | Default scrolling background, primary text, and secondary icons/captions |
| `surfaceContainerLowest`..`Highest` | Nested container hierarchy (`Card`, lists, `SearchBar`, sheets, drawers) without fake blur |
| `outline` / `outlineVariant` | `1dp` borders on `OutlinedCard`/`OutlinedButton` (`outline`) and subtle dividers (`outlineVariant`) |
| `error` / `onError` / `errorContainer` | Validation errors, destructive confirmations, alert banners (paired with icon + text) |

Shape and `8dp` / `4dp` grid rules:
- M3 `Shapes`: `extraSmall = 4.dp` (menus, snackbars, text fields), `small = 8.dp` (chips, rich tooltips), `medium = 12.dp` (cards, small dialogs), `large = 16.dp` (standard FABs, nav drawers), `extraLarge = 28.dp` (bottom sheets, large dialogs, large FABs).
- Baseline spacing grid: `4dp` increments with `16dp` outer horizontal margin on compact screens (`24dp` on medium/expanded panes), `8dp` between related controls, and minimum `48dp x 48dp` interactive touch area (`minimumInteractiveComponentSize`).

## 4. Edge-to-edge, adaptive navigation, and gestures

Designing for Android mobile (`https://developer.android.com/design/ui/mobile`) requires responsive adaptation from portrait phones to large tablets and foldables:
- **Edge-to-edge (`enableEdgeToEdge()`)**: Draw behind transparent system status and navigation bars in every `Activity`. Pass `Scaffold` `innerPadding` strictly to scrollable content, or combine `WindowInsets.safeDrawing` / `WindowInsets.systemBars` + `WindowInsets.ime` (for smooth software-keyboard inset handling) on root panes.
- **Canonical adaptive Window Size Classes**:
  - **Compact (`width < 600dp`, typical phones)**: Bottom `NavigationBar` with `3-5` destinations (sentence-case concise labels, `alwaysShowLabel`), single-column `LazyColumn` with `16dp` side padding, primary action in `FloatingActionButton` or bottom bar.
  - **Medium (`600dp <= width < 840dp`, foldables / portrait tablets)**: Automatically switch bottom bar to a left-hand `NavigationRail` (`NavigationSuiteScaffold`), keep single primary pane (`<= 640dp` readable measure) or complementary pane.
  - **Expanded (`width >= 840dp`, landscape tablets / foldables / Desktop Android)**: Promote to `NavigationRail` or `PermanentNavigationDrawer`, and adopt canonical two-pane layouts (`ListDetailPaneScaffold` or `SupportingPaneScaffold`) with drag handle Resize affordance rather than stretched full-width mobile buttons.
- **Predictive back and motion**: Handle navigation back predictively (`NavHost` / `PredictiveBackHandler` instead of overriding `onBackPressed()`), use system physics springs/shared-axis transitions sparingly, and honor `Settings.Global.ANIMATOR_DURATION_SCALE == 0` reduced-motion preferences.

## 5. Accessibility and Jetpack Compose / Material 3 mapping

- **Contrast and TalkBack**: Meet `>= 4.5:1` contrast (`>= 3.0:1` for large text and graphical controls) across light and dark themes (never assume dynamic wallpaper colors alone have high contrast outside M3 paired `on*` roles). Provide `contentDescription` on every meaningful icon/image (`null` only on decorative elements), `Modifier.semantics(mergeDescendants = true)` on composite list rows so TalkBack reads a whole item cleanly in one swipe, `heading()` semantics on section titles, and `liveRegion` on status updates.
- **Jetpack Compose APIs**:
  - Wrap root UI in `MaterialTheme` using `dynamicDarkColorScheme(context)` / `dynamicLightColorScheme(context)` on Android 12+ (`Build.VERSION.SDK_INT >= Build.VERSION_CODES.S`) falling back to clean light/dark static `ColorScheme`.
  - Use official Material 3 composables (`Scaffold`, `TopAppBar`, `LargeTopAppBar`, `NavigationSuiteScaffold`, `ListItem`, `ModalBottomSheet`, `PullToRefreshBox`, `ExposedDropdownMenuBox`, `SnackbarHost`) rather than reimplementing raw `Box` + `clickable` chrome.
  - Run heavy I/O and state reduction off `Dispatchers.Main` (`viewModelScope`, `StateFlow`, `collectAsStateWithLifecycle`) so scroll frames stay locked without jank.
"##;

pub const APPLE_HIG_DESIGN_SKILL: &str = r##"---
name: apple-hig-design
description: >-
  Native Apple Human Interface Guidelines (HIG) design standard for iOS, iPadOS, and macOS using
  SwiftUI, UIKit, and AppKit. Enforces SF Pro typography and Dynamic Type, semantic system colors
  and Vibrancy materials, safe areas, 44pt iOS touch targets, macOS split-view/toolbar/menu bar
  conventions, VoiceOver accessibility, and zero AI-slop styling.
---

# Native Apple Human Interface Guidelines (iOS, iPadOS, and macOS)

Grounds every Apple mobile and desktop interface in official Apple Human Interface Guidelines:
- Human Interface Guidelines: https://developer.apple.com/design/human-interface-guidelines
- Designing for iOS: https://developer.apple.com/design/human-interface-guidelines/designing-for-ios
- Designing for macOS: https://developer.apple.com/design/human-interface-guidelines/designing-for-macos

## 1. Anti-AI-slop prohibitions on Apple platforms

Never ship generic dark-purple SaaS templates or web wrappers styled as native Apple apps:
- **Zero neon gradients or synthetic chrome**: Do not coat cards, headers, or toolbars in saturated purple/cyan gradients or thick web box-shadows.
- **Zero fake glassmorphism blobs**: Never roll custom blur rectangles or stacked frosted panels; rely strictly on system `Material` (`.ultraThinMaterial`, `.regularMaterial`) or `NSVisualEffectView` for sidebars, toolbars, and transient overlays.
- **Zero desktop chrome on iOS or mobile chrome on macOS**: Never put hamburger drawers or tiny `24pt` toolbar buttons on iPhone, and never put bottom mobile tab bars or oversized pill buttons inside macOS windows.
- **Zero custom title-bar hacks obscuring system controls**: Always respect Dynamic Island, Home indicator safe areas, and macOS traffic-light window controls (`close`/`minimize`/`zoom`).
- **Zero unscalable fixed fonts or harsh dividers**: Never lock body text to non-scaling points on iOS, and never hardcode `#FFFFFF`/`#000000` where semantic system colors adapt automatically.

## 2. Typography (`SF Pro`), Dynamic Type, and `SF Symbols`

Use native Apple system font families (`SF Pro` on iOS/iPadOS/macOS, `SF Mono` for code/keys/endpoints, optional `New York` for editorial prose). Use Regular (`400`), Medium (`500`), or Semibold (`600`) for hierarchy rather than uniform Bold (`700`) everywhere, and apply sentence case (title case strictly for macOS Menu Bar items and macOS alert/push button titles per Apple convention).

| Text style | iOS / iPadOS default (`pt`, scales via Dynamic Type) | macOS default (`pt`) | Usage |
| :--- | :--- | :--- | :--- |
| `largeTitle` | `34 / 41` (Regular) | `26 / 32` (Regular) | Scrollable top view header transitioning inline on scroll |
| `title` / `title2` / `title3` | `28/34`, `22/28`, `20/25` | `22/26`, `17/22`, `15/20` | View sections, sheets, split headers |
| `headline` | `17 / 22` (Semibold) | `13 / 16` (Bold/Semibold) | Section/card titles, emphasis |
| `body` | `17 / 22` (Regular) | `13 / 16` (Regular) | Primary reading copy, list rows |
| `callout` / `subheadline` | `16/21`, `15/20` | `12/15`, `11/14` | Secondary labels, form hints |
| `footnote` / `caption` / `caption2` | `13/18`, `12/16`, `11/13` | `10/13` | Footnotes, timestamps, chart ticks |

- **Dynamic Type**: Support full Accessibility Extra Large sizes (`AX1`-`AX5`) via system text styles (`.body`, `.headline`, `@ScaledMetric`), reflowing multi-column horizontal rows vertically (`ViewThatFits` / `DynamicTypeSize.isAccessibilitySize`) when text grows.
- **SF Symbols**: Prefer standard `SF Symbols` with hierarchical, monochrome, or palette rendering matched cleanly to surrounding text weight instead of custom raster PNGs.

## 3. Semantic colors, luminance, and vibrancy materials

Always use semantic system colors so Light Mode, Dark Mode, Increase Contrast, and inactive window states render natively:

| Semantic role | Apple token (`SwiftUI` / `UIKit` / `AppKit`) | Guidance |
| :--- | :--- | :--- |
| Window / page base | `Color(.systemBackground)` / `Color(.windowBackgroundColor)` | Pure white/charcoal base (`macOS` adapts subtle window fill) |
| Grouped table canvas | `Color(.systemGroupedBackground)` / `Color(.controlBackgroundColor)` | Subtle canvas behind inset grouped cards |
| Elevated surface | `Color(.secondarySystemGroupedBackground)` / `Color(.underPageBackgroundColor)` | Grouped list rows and detail panels |
| Primary / secondary label | `.primary` (`labelColor`), `.secondary` (`secondaryLabelColor`) | Crisp `>= 4.5:1` foreground hierarchy |
| Hairline separator | `Color(.separator)` / `Divider()` | `0.5pt`-`1px` native translucent divider |
| App accent tint | `.tint(...)` / `Color.accentColor` (`controlAccentColor`) | Single user/brand accent (`macOS` honors multicolor vs graphite accent preference!) |
| Materials & vibrancy | `.ultraThinMaterial`..`.thickMaterial` / `NSVisualEffectView` | Strictly on sidebars, nav bars, tab bars, popovers, sheets |

Always degrade translucent materials cleanly to opaque high-contrast fills when `accessibilityReduceTransparency` or `accessibilityContrast` is enabled.

## 4. Designing for iOS and iPadOS (`designing-for-ios`)

Build clarity, deference, and thumb-reachable ergonomics around touch and portrait/compact geometry:
- **Safe areas and ergonomics**: Keep all interactive controls inside `safeAreaInsets` (never under Status Bar, Dynamic Island, or Home Indicator); place primary navigation and frequent actions within bottom thumb reach (`TabView` with `3-5` flat top-level destinations; never exceed `5` tabs or bury tabs inside a hamburger menu).
- **Touch geometry (`44pt x 44pt`)**: Every interactive button, toggle, or bar item must expose at least a `44pt x 44pt` hit region even when its glyph is smaller (`contentShape(Rectangle())`). Maintain at least `8pt` clearance between adjacent tap targets.
- **Native containers and smooth squircles**: Use `NavigationStack` (large title collapsing into translucent top bar), `List` with `.insetGrouped` style (`10pt`-`12pt` `.continuous` squircle corners on grouped sections), native `.sheet` with `.presentationDetents([.medium, .large])` and grabber handle, and `.confirmationDialog` / `.swipeActions` instead of tiny inline action buttons.
- **Haptic & fluid feedback**: Trigger subtle contextual `.sensoryFeedback(...)` on meaningful toggles, completions, or warnings, avoid blocking spinners where optimistic updates or pull-to-refresh (`.refreshable`) work, and adapt cleanly on iPadOS using `NavigationSplitView` + sidebar + `UIHoverStyle` pointer effects.

## 5. Designing for macOS (`designing-for-macos`)

Design for precision pointer input, multitasking windows, keyboard shortcuts, and native Menu Bar conventions:
- **Pointer density (`20pt-28pt`)**: Avoid inflated `44pt` mobile touch bars on Mac; use crisp macOS `.controlSize(.regular)` (`20-24pt` height) or `.large` (`28pt` primary forms), `10-12pt` window corners, `6-8pt` grouped card radii, and `5-6pt` button/input radii (`NSBezelStyle`).
- **Window layout (`NavigationSplitView` + Unified Toolbar)**: Use a full-height translucent `.sidebar` (`.listStyle(.sidebar)`, source list material) paired with `.toolbar` items cleanly aligned alongside traffic-light window controls. Do not replicate in-window links for standard commands (`Save`, `Print`, `Close`, `Settings`); put them in the system **Menu Bar** via `.commands { ... }` and wire `Command+,` (`Settings` scene) for preferences.
- **Desktop behaviors**: Support rich right-click `.contextMenu`, drag-and-drop, multi-window / `TabGroup` workflows, clear `.keyboardShortcut(...)` bindings, arrow/Tab navigation (`focusable()`), dimming of active controls when the window loses key focus, non-blocking `Alert` sheets or `NSUserNotification`, and complete `VoiceOver` (`accessibilityLabel`, `accessibilityHint`, `accessibilityAddTraits`).
"##;

pub const LINUX_DESKTOP_HIG_DESIGN_SKILL: &str = r##"---
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
"##;

pub const PERSONAL_DESIGN_SKILLS: &[(&str, &str)] = &[
    ("windows-app-design", WINDOWS_APP_DESIGN_SKILL),
    ("android-app-design", ANDROID_APP_DESIGN_SKILL),
    ("apple-hig-design", APPLE_HIG_DESIGN_SKILL),
    ("linux-desktop-hig-design", LINUX_DESKTOP_HIG_DESIGN_SKILL),
];
