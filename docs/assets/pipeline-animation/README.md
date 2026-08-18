# Pipeline animation source

`index.html` is the source for `../pipeline.gif` (embedded at the top of the project
README) and `../pipeline.mp4`. It is a [HyperFrames](https://hyperframes.heygen.com)
composition — a plain HTML file whose DOM declares its own timing and whose animation is a
single paused GSAP timeline, rendered to video frame by frame.

It is committed so the animation is reproducible rather than an unexplained binary: edit
the HTML, re-render, and both outputs regenerate.

## Regenerating

```bash
npx hyperframes render . -o ./renders/video.mp4
```

Then re-encode the GIF (two-pass palette — the content is flat colour, which GIFs
efficiently; this lands ~275 KB where a naive encode is several MB):

```bash
ffmpeg -y -i renders/video.mp4 \
  -vf "fps=12,scale=920:-1:flags=lanczos,palettegen=max_colors=64:stats_mode=diff" \
  palette.png

ffmpeg -y -i renders/video.mp4 -i palette.png \
  -lavfi "fps=12,scale=920:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" \
  pipeline.gif
```

Copy `renders/video.mp4` to `../pipeline.mp4` and `pipeline.gif` to `../pipeline.gif`.

## Note on the render

The composition's background fill sits on a full-bleed child inside the clip, not on the
composition root. A fill on the root itself is dropped by the frame compositor and every
frame renders black — which, with near-black text on white, looks like a completely empty
video rather than a missing background.
