---
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
