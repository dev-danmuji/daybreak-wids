#!/usr/bin/env bash
# Render the README animation from docs/animation/daybreak_flow.py:
#   Manim  -> docs/assets/daybreak-flow.mp4  (1280x720, 30 fps)
#   ffmpeg -> docs/assets/daybreak-flow.gif  (900 px wide, 15 fps, looping, at most 8 MB)
#
# Needs Manim Community Edition (checked against 0.21) and ffmpeg on PATH. This
# script installs nothing, makes no network requests (manim --silent) and
# changes nothing outside docs/assets/; see docs/animation/README.md for the
# install commands.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
assets=$(cd "$here/../assets" && pwd)
manim=${MANIM:-manim}
max_bytes=$((8 * 1024 * 1024))

missing=0
if ! command -v "$manim" >/dev/null 2>&1; then
  echo "manim not found (set MANIM=/path/to/manim): see docs/animation/README.md" >&2
  missing=1
fi
if ! command -v ffmpeg >/dev/null 2>&1; then
  echo "ffmpeg not found: see docs/animation/README.md" >&2
  missing=1
fi
[ "$missing" -eq 0 ] || exit 1

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

"$manim" render --resolution 1280,720 --frame_rate 30 --disable_caching --silent --media_dir "$work" \
  "$here/daybreak_flow.py" DaybreakFlow
video=$(find "$work/videos" -name DaybreakFlow.mp4 -print -quit)
if [ -z "$video" ]; then
  echo "manim did not produce DaybreakFlow.mp4" >&2
  exit 1
fi
cp "$video" "$assets/daybreak-flow.mp4"

# One palette for the whole clip, weighted towards what changes between frames
# (stats_mode=diff, one slot kept transparent so unchanged pixels cost nothing);
# ordered (Bayer) dithering stays stable from frame to frame, and
# diff_mode=rectangle re-maps only the part of each frame that changed.
# Fallbacks change one thing at a time; the first result of at most 8 MB is kept.
gif=""
for spec in 900:15:256 900:12:256 900:12:128 800:12:256 720:12:256; do
  IFS=: read -r width fps colors <<< "$spec"
  out="$work/flow-${width}-${fps}-${colors}.gif"
  ffmpeg -hide_banner -v error -y -i "$assets/daybreak-flow.mp4" -filter_complex \
    "[0:v]fps=${fps},scale=${width}:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=${colors}:reserve_transparent=1:stats_mode=diff[p];[s1][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" \
    -loop 0 "$out"
  size=$(wc -c < "$out" | tr -d ' ')
  echo "GIF ${width} px, ${fps} fps, ${colors} colours: ${size} bytes"
  gif=$out
  if [ "$size" -le "$max_bytes" ]; then
    break
  fi
done
if [ "$size" -gt "$max_bytes" ]; then
  echo "warning: the GIF is still larger than 8 MB; shorten holds or reduce full-frame motion in the scene" >&2
fi
cp "$gif" "$assets/daybreak-flow.gif"

if command -v ffprobe >/dev/null 2>&1; then
  for f in "$assets/daybreak-flow.mp4" "$assets/daybreak-flow.gif"; do
    ffprobe -v error -select_streams v:0 -show_entries stream=width,height:format=duration,size \
      -of default=noprint_wrappers=1 "$f" | tr '\n' ' '
    echo " <- $f"
  done
fi
