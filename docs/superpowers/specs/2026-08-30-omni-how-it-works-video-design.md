# OMNI How It Works Video

## Goal

Create a new 25-second video that closely follows the visual language and pacing of Linear's orbital workflow animation while replacing its labels with OMNI's How it works narrative.

## Fixed visual constraints

- 1920x1080 output at 60 fps.
- Black monochrome scene with thin orbital paths, moving nodes, radial ticks, restrained glow, depth blur, film grain, and slow cinematic camera movement.
- Match the reference shot order and pacing: close orbital reveal, process traversal, camera pullback, second assessment sequence, and final system view.
- Do not add cards, panels, subtitles, colored shapes, or page UI inside the video.
- Preserve the original reference audio track for timing and atmosphere.

## Text sequence

1. `REQUEST ENTERS OMNI`
2. `PREFLIGHT STARTS`
3. `CHECK PACKAGE RISK`
4. `CHECK REPOSITORY HISTORY`
5. `VERIFY SERVICE IDENTITY`
6. `SERVICE CHECK COMPLETE`
7. `PAYMENT TERMS CAPTURED`
8. `CHECK PAYMENT CONFIG`
9. `REVIEW ASSESSMENT`
10. `READ SOURCE EVIDENCE`
11. `ACT WITH CLEAR CONTEXT`

## Implementation boundary

This is a new render modeled after the reference, not a pixel-level modification of Linear's flattened MP4. The recreated scene should remain visually faithful while all authored labels describe OMNI.

## Delivery

- Render the first 25 seconds to `frontend/public/omni-how-it-works-25s.mp4`.
- Keep the existing How it works video element and tutorial layout.
- Validate codec metadata, representative frames, frontend build, responsive layout, and playback in the existing local preview.
