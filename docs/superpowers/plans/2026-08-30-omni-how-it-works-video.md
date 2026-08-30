# OMNI How It Works Video Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render a 25-second OMNI workflow animation that closely matches the monochrome orbital motion language of the supplied Linear reference while using only OMNI labels.

**Architecture:** A temporary deterministic Python renderer builds every frame from projected 3D orbital geometry using NumPy and Pillow, then streams RGB frames to FFmpeg. FFmpeg encodes H.264 at 1920x1080/60 fps and remuxes the first 25 seconds of the official reference audio. The website continues to consume one static MP4 from `frontend/public`.

**Tech Stack:** Python 3, NumPy, Pillow, FFmpeg, React/Vite.

## Global Constraints

- Output is exactly 25 seconds, 1920x1080, and 60 fps.
- Use black, white, and restrained gray only.
- Include orbital paths, radial ticks, moving nodes, glow, depth blur, film grain, and cinematic camera movement.
- Do not add cards, panels, subtitles, colored shapes, or page UI inside the video.
- Use the approved eleven OMNI labels verbatim.
- Do not add project dependencies or commit changes.

---

### Task 1: Deterministic orbital renderer

**Files:**
- Create: `../video-inspect/render_omni_orbit.py`
- Produce: `../video-inspect/omni-how-it-works-silent.mp4`

**Interfaces:**
- Consumes: frame number, 60 fps timeline, 1920x1080 canvas, approved label list.
- Produces: H.264 MP4 with exactly 1500 video frames and no audio.

- [ ] Define rotation, camera projection, orbit sampling, tangent direction, and label anchor helpers.
- [ ] Render sharp geometry and separate glow/depth layers for each frame.
- [ ] Render the approved labels as transformed monochrome text attached to orbit anchors.
- [ ] Add deterministic low-amplitude grain and vignette without color shifts.
- [ ] Stream RGB frames to FFmpeg using `libx264`, `-crf 15`, `yuv420p`, and `+faststart`.
- [ ] Run the renderer and verify it exits with code 0.

### Task 2: Audio and delivery asset

**Files:**
- Consume: `../video-inspect/linear-x-original-4k.mp4`
- Produce: `frontend/public/omni-how-it-works-25s.mp4`

**Interfaces:**
- Consumes: silent OMNI render and the first 25 seconds of the reference AAC track.
- Produces: browser-compatible H.264/AAC MP4.

- [ ] Remux the rendered video with the reference audio using FFmpeg.
- [ ] Trim to 25.000 seconds and write `frontend/public/omni-how-it-works-25s.mp4`.
- [ ] Verify resolution, frame rate, codec, audio codec, duration, and file size with FFprobe.

### Task 3: Visual comparison and correction

**Files:**
- Produce temporarily: `../video-inspect/omni-contact-sheet.jpg`

**Interfaces:**
- Consumes: final MP4.
- Produces: representative frames at two-second intervals for visual inspection.

- [ ] Extract a 0-25 second contact sheet.
- [ ] Compare pacing, orbit density, contrast, label scale, glow, and camera distance with the official reference sheet.
- [ ] Correct the renderer once if a major mismatch is visible, then rerender and reinspect.

### Task 4: Frontend validation

**Files:**
- Verify: `frontend/src/App.tsx`
- Verify: `frontend/src/styles.css`
- Verify: `frontend/public/omni-how-it-works-25s.mp4`

**Interfaces:**
- Consumes: existing `<video>` integration.
- Produces: playable responsive How it works section.

- [ ] Run `npm run build` from `frontend`.
- [ ] Run `git diff --check` and review `git status --short`.
- [ ] Reload `http://127.0.0.1:4173/#evidence`, confirm playback, and check desktop/mobile overflow and console errors.
- [ ] Preserve the already-running local preview because the user explicitly requested it remain open.
