# README animation

`daybreak_flow.py` is the [Manim](https://www.manim.community/) source of the
animation at the top of the project README:

- `docs/assets/daybreak-flow.mp4`: 1280 × 720, 30 fps, 14.6 s, 0.9 MB (H.264)
- `docs/assets/daybreak-flow.gif`: 900 × 506, 15 fps, 14.6 s, looping, 2.8 MB

It shows how a detection is built: a protected access point and its four
clients, a deauthentication burst that disconnects them, the clients
reconnecting and re-authenticating (EAPOL), both observations going into
Daybreak's correlation engine, the risk score adding up one listed component at
a time, the resulting `POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT` alert, and the
closing lines "Passive defensive monitoring only" and "No packet injection / No
credential cracking".

All values are synthetic: the README's example network (`ExampleSSID`) and no
MAC addresses. The numbers are the README's default-weights example ("Why this
exists", pinned by `tests/test_correlation.py`), in the order the correlation
engine adds them: deauth burst 30 (LOW), several clients affected +15 (45, LOW),
the same clients re-authenticate +10 (55, MEDIUM), EAPOL reauthentication surge
+17 (72, HIGH). The final card reads "HIGH / CRITICAL" and notes that the
README demo replay, which has more signals, reaches 95, CRITICAL. The scene only
draws: no attacker or attack tool is shown, nothing moves away from the sensor,
and no frames are captured, crafted or replayed. Colours are the dashboard's
dark theme.

## How the committed files were made

With Manim Community 0.21.0 and ffmpeg 9.0.2 in a local, disposable environment
outside the repository (nothing installed system-wide): pycairo and ManimPango
have no Linux wheels and need the Cairo / Pango development headers, so the
native libraries came from conda-forge through a standalone `micromamba`, and
Manim from PyPI on top:

```bash
env=~/.cache/daybreak-wids-render/env
micromamba create -p "$env" -c conda-forge python=3.12 "pycairo>=1.14,<2" "manimpango>=0.6.1,<1" ffmpeg pip
"$env/bin/python" -m pip install "manim==0.21.0"
PATH="$env/bin:$PATH" MANIM="$env/bin/manim" docs/animation/render.sh
```

Delete `~/.cache/daybreak-wids-render` afterwards to remove all of it. The
system-package route below works as well.

## Requirements

Install these yourself; `render.sh` installs nothing.

- **Manim Community Edition 0.21** (the version the scene was checked against;
  it needs Python 3.11 or newer). Manim writes the MP4 through PyAV, so
  rendering needs no ffmpeg binary, and the scene uses `Text` only, so LaTeX is
  not needed (`manim checkhealth` may still warn about it). On Linux, pycairo and
  ManimPango build from source, so install the build dependencies first, then
  Manim in its own virtual environment, not in the project's:

  ```bash
  # Debian / Ubuntu
  sudo apt install build-essential python3-dev pkg-config libcairo2-dev libpango1.0-dev python3-venv
  # Fedora (gcc-c++ builds moderngl / glcontext on Python 3.14)
  sudo dnf install python3-devel pkg-config cairo-devel pango-devel gcc gcc-c++
  # macOS (Homebrew)
  brew install cairo pkg-config

  python3 -m venv ~/.venvs/manim
  ~/.venvs/manim/bin/pip install "manim==0.21.*"
  ```

  The [Manim installation guide](https://docs.manim.community/en/stable/installation.html)
  also describes an install with `uv`.

- **ffmpeg** for the GIF:

  ```bash
  sudo apt install ffmpeg     # Debian / Ubuntu
  brew install ffmpeg         # macOS
  ```

  On Fedora use the full `ffmpeg` from RPM Fusion: Fedora's own `ffmpeg-free`
  cannot reliably decode the H.264 High-profile MP4 that Manim writes.

- The fonts **DejaVu Sans** and **DejaVu Sans Mono** (preinstalled on most Linux
  systems; `fonts-dejavu-core` on Debian / Ubuntu). If they are missing, Manim
  logs a warning and Pango substitutes another font; text sizes stay the same
  because the scene sizes text from a measured reference glyph.

## Render

```bash
MANIM=~/.venvs/manim/bin/manim docs/animation/render.sh
```

`render.sh` renders the scene at 1280 × 720 and 30 fps into a temporary media
directory (`--silent`: no update check over the network), copies the MP4 to
`docs/assets/daybreak-flow.mp4`, converts it to `docs/assets/daybreak-flow.gif`,
and prints the size, resolution and duration of both files. The same steps by
hand:

```bash
manim render --resolution 1280,720 --frame_rate 30 --disable_caching --silent \
    --media_dir /tmp/daybreak-manim docs/animation/daybreak_flow.py DaybreakFlow
cp /tmp/daybreak-manim/videos/daybreak_flow/720p30/DaybreakFlow.mp4 docs/assets/daybreak-flow.mp4

ffmpeg -hide_banner -y -i docs/assets/daybreak-flow.mp4 -filter_complex \
  "[0:v]fps=15,scale=900:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=256:reserve_transparent=1:stats_mode=diff[p];[s1][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" \
  -loop 0 docs/assets/daybreak-flow.gif
```

- `fps=15` first, so scaling and palette work see 210 frames; `scale` with
  `lanczos` keeps small text sharp.
- `palettegen` builds one palette for the whole clip; `stats_mode=diff` weights
  the colours of what changes between frames, and the reserved transparent slot
  lets the GIF encoder store unchanged pixels for free.
- `paletteuse` with ordered (Bayer) dithering keeps the pattern stable from
  frame to frame; `diff_mode=rectangle` re-maps only the changed part of each
  frame.
- `-loop 0` (after `-i`, as an output option) loops forever.

If the GIF is larger than 8 MB, `render.sh` retries with 12 fps, then 128
colours, then 800 px and 720 px wide (still 12 fps), and keeps the first result
that fits. The committed GIF needed no fallback (2.8 MB at 900 px and 15 fps).
The README shows the GIF at its own width, so a smaller fallback would not be
upscaled.

For a quick low-resolution preview while editing the scene:
`manim render -ql -p docs/animation/daybreak_flow.py DaybreakFlow`.

## Check before publishing

- Duration 10–15 s, the GIF about 900 px wide and at most 8 MB
  (`render.sh` prints these; or `ffprobe docs/assets/daybreak-flow.gif`).
- Every text is readable at the size GitHub shows the GIF, and nothing overlaps.
- Only the synthetic values above appear: no real SSID, BSSID or MAC address.

## In the README

`README.md` shows the GIF right below the safety notice, with an alt text that
describes every step and a link to the MP4 (GitHub plays MP4 files only when
they are uploaded as attachments, so the repository copy is a link). The short
"How a detection is built" paragraph below it explains the same flow in words,
for viewers whose GIFs do not load or do not autoplay. `tests/test_readme.py`
checks that every image the README shows exists and that the animation is shown
whenever `docs/assets/daybreak-flow.gif` exists.
