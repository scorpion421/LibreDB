---
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
