# Design System Specification: The Command Architect

## 1. Overview & Creative North Star
The Creative North Star for this design system is **"The Command Architect."** 

This system moves away from the cluttered, "noisy" dashboards of the past, opting instead for a high-fidelity, tactical aesthetic inspired by professional Linux environments and high-end security consoles. We are building an interface that feels like a precision instrument—calm, authoritative, and deeply intentional. 

To break the "template" look, we avoid rigid grids in favor of **Intentional Asymmetry**. Larger data visualizations should breathe, while terminal-style micro-copy provides the technical "grain" that gives the UI its soul. We use overlapping surfaces and varying tonal depths to guide the eye, creating a sense of sophisticated hierarchy that feels engineered rather than merely "designed."

---

## 2. Colors & Surface Logic
The palette is rooted in the Nord Dark philosophy: deep, atmospheric slates and charcoal blues paired with frosty, high-legibility typography.

### The "No-Line" Rule
**Explicit Instruction:** Designers are prohibited from using 1px solid borders for sectioning or layout containment. Structural boundaries must be defined solely through:
1.  **Background Color Shifts:** Placing a `surface_container_low` (#161c27) section against a `surface` (#0d131e) background.
2.  **Tonal Transitions:** Using the hierarchy of containers to suggest depth without the visual "noise" of lines.

### Surface Hierarchy & Nesting
Treat the UI as a series of physical layers. Use the surface-container tiers to create a logical "nest":
*   **Base:** `surface` (#0d131e)
*   **Deep Inset:** `surface_container_lowest` (#080e19) for background utility areas.
*   **Standard Cards:** `surface_container` (#1a202b).
*   **Raised/Active Elements:** `surface_container_highest` (#2f3541).

### The "Glass & Gradient" Rule
For floating modals or high-level overlays, use **Glassmorphism**. Apply a semi-transparent `surface_container_high` (#242a36) with a `backdrop-blur` of 12px to 20px. 

### Signature Textures
Main CTAs and Hero elements should not be flat. Apply a subtle linear gradient (Top-Left to Bottom-Right) transitioning from `primary` (#a3dcec) to `primary_container` (#88c0d0). This adds a "metallic" sheen that mimics high-end hardware interfaces.

---

## 3. Typography
We utilize a dual-typeface system to balance technical precision with modern editorial flair.

*   **The Display Layer (Space Grotesk):** Used for `display` and `headline` roles. This typeface provides a geometric, almost monospaced personality that echoes terminal outputs while maintaining a premium feel.
*   **The Content Layer (Inter):** Used for `title`, `body`, and `label`. Inter provides maximum readability for dense security logs and data points.

**Hierarchy Strategy:** 
Maintain high contrast between `display-lg` (3.5rem) and `label-sm` (0.6875rem). The goal is to make the "big numbers" feel like architectural statements, while the supporting data remains clean and zero-clutter.

---

## 4. Elevation & Depth
Depth in this design system is achieved through **Tonal Layering** rather than traditional drop-shadows.

### The Layering Principle
Stacking containers creates natural lift. For example:
*   A user profile card (`surface_container_low`) sitting on a dashboard rail (`surface_container_lowest`) creates an immediate, soft visual hierarchy.

### Ambient Shadows
When an element must "float" (e.g., a dropdown or a floating action button), use a shadow with a blur value of `24px` to `40px` at an opacity of **4% to 8%**. The shadow color must be a tinted version of the background (`#080e19`), never pure black, to simulate natural ambient light.

### The "Ghost Border" Fallback
If an element requires containment for accessibility, use a **Ghost Border**:
*   Stroke: `outline_variant` (#40484b)
*   Opacity: 15%
*   Weight: 1px

---

## 5. Components

### Buttons
*   **Primary:** Gradient of `primary` to `primary_container`. Text color `on_primary` (#003640). Radius: `md` (0.375rem).
*   **Secondary:** Ghost style. No background fill, only a `Ghost Border` (15% opacity outline) with `primary` colored text.
*   **Tertiary:** Transparent background. Subtle `on_surface_variant` text that shifts to `primary` on hover.

### Input Fields
*   **Style:** Terminal-inspired. `surface_container_lowest` fill.
*   **Focus State:** No thick border. Instead, use a subtle `0 0 8px` outer glow in the `primary` (#a3dcec) color at 30% opacity.

### Cards & Lists
*   **NO DIVIDERS:** Separation is achieved through `1.5` (0.3rem) to `3` (0.6rem) spacing increments or subtle shifts in surface tone.
*   **List Item:** On hover, a list item should transition to `surface_container_high` with a `sm` (0.125rem) rounded corner.

### Tactical Components (Dashboard Specific)
*   **The "Health Pulse":** A small, muted yellow or red glow (`error` or `tertiary_fixed_dim`) used next to server names to indicate status without loud, flashing banners.
*   **Terminal Micro-Log:** A `body-sm` text block using `on_surface_variant` for displaying real-time system pings.

---

## 6. Do's and Don'ts

### Do:
*   **Embrace the Dark:** Use the `surface` and `surface_dim` tokens to create a sense of infinite depth.
*   **Use Precise Geometry:** Stick strictly to the Roundedness Scale—subtle `0.25rem` corners are the default for a professional, "machined" look.
*   **Prioritize White Space:** Use the Spacing Scale to let complex security data "breathe."

### Don't:
*   **Don't use 100% Opaque Borders:** This creates a "boxed-in" feel that ruins the premium terminal aesthetic.
*   **Don't use High-Saturation Colors:** Avoid bright neons. Stick to the muted, "frosty" tones of the Nord-inspired palette.
*   **Don't use Standard Shadows:** Never use high-opacity, small-blur shadows. They feel "cheap" and dated.