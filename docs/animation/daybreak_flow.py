"""Daybreak WIDS detection flow: the short animation for the top of README.md.

A protected access point and its clients, a deauthentication burst, the clients
reconnecting and re-authenticating, both observations going into Daybreak's
correlation engine, the risk score adding up, and the resulting alert.

Every value is synthetic. The network is the README's example (``ExampleSSID``),
no addresses are shown, and the numbers are the README's default-weights example
("Why this exists"; pinned by tests/test_correlation.py), in the order the
engine adds them: deauth burst 30, several clients affected +15, the same clients
re-authenticate +10, EAPOL reauthentication surge +17 = 72, HIGH. The README demo
replay adds more signals and reaches 95, CRITICAL; the final card says both.
Nothing is captured, sent or replayed: this file only draws, and nothing in it
moves away from the sensor.

Rendered with Manim Community Edition 0.21.0 and converted to a GIF with ffmpeg
(docs/assets/daybreak-flow.mp4 / .gif); to re-render, run
``docs/animation/render.sh`` (see docs/animation/README.md).
"""

from __future__ import annotations

from manim import (
    BOLD,
    DOWN,
    LEFT,
    NORMAL,
    RIGHT,
    UP,
    Circle,
    Dot,
    FadeIn,
    FadeOut,
    LaggedStart,
    Line,
    Rectangle,
    RoundedRectangle,
    Scene,
    Succession,
    Text,
    ValueTracker,
    VGroup,
    always_redraw,
    config,
    linear,
    smooth,
    there_and_back,
)

# Colours of the dashboard's dark theme (daybreak/dashboard/static/style.css).
BG = "#11151c"
CARD = "#1a2029"
LINE = "#2b3340"
TEXT = "#e3e8ef"
MUTED = "#8d99ab"
ACCENT = "#6ea2ff"
OK = "#46c27b"
INFO = "#8d99ab"
LOW = "#4fb3dc"
MEDIUM = "#e8b03a"
HIGH = "#f06a52"
CRITICAL = "#ff4d6a"
DEAUTH = "#d4472f"   # event colours of the dashboard timeline
EAPOL = ACCENT

SANS = "DejaVu Sans"
MONO = "DejaVu Sans Mono"

# Risk bands (daybreak/models.py: Severity.from_score).
BANDS = (
    (0, 30, "INFO", INFO),
    (30, 50, "LOW", LOW),
    (50, 70, "MEDIUM", MEDIUM),
    (70, 90, "HIGH", HIGH),
    (90, 101, "CRITICAL", CRITICAL),
)
# (score after the component, the component as the alert lists it)
SCORE_STEPS = (
    (30, "+30  deauth burst"),
    (45, "+15  several clients affected"),
    (55, "+10  same clients re-authenticate"),
    (72, "+17  EAPOL reauthentication surge"),
)

# Text sizes are cap heights in scene units. The frame is 8 units high, so in a
# 900 px wide 16:9 GIF one unit is about 63 px: 0.165 units is a 10.4 px cap height.
CAP_CAPTION = 0.2
CAP_LABEL = 0.19
CAP_SMALL = 0.165
CAP_TAG = 0.15
CAP_CARD = 0.19
CAP_ENGINE = 0.21
CAP_SCORE = 0.4
CAP_BAND = 0.19
CAP_COMPONENT = 0.17
CAP_ALERT = 0.32
CAP_ALERT_TYPE = 0.22
CAP_FOOTER = 0.2

config.background_color = BG

_cap_cache: dict[tuple[str, str], float] = {}
_text_cache: dict[tuple, Text] = {}


def text(s: str, cap: float, *, color: str = TEXT, bold: bool = False, mono: bool = False) -> Text:
    """``s`` with a capital letter exactly ``cap`` units high.

    Sizing from a measured reference glyph keeps the layout the same whatever
    point-to-unit conversion the local Pango / Cairo build uses. Each distinct
    text is built once and copied afterwards (the meter redraws every frame).
    """
    key = (s, cap, color, bold, mono)
    if key not in _text_cache:
        font = MONO if mono else SANS
        weight = BOLD if bold else NORMAL
        if (font, weight) not in _cap_cache:
            _cap_cache[font, weight] = Text("H", font=font, weight=weight, font_size=48).height
        mob = Text(s, font=font, weight=weight, font_size=48, color=color)
        _text_cache[key] = mob.scale(cap / _cap_cache[font, weight])
    return _text_cache[key].copy()


def fit(mob, max_width: float):
    """Scale ``mob`` down (never up) so it is at most ``max_width`` wide."""
    if mob.width > max_width:
        mob.scale_to_fit_width(max_width)
    return mob


def box(width: float, height: float, stroke: str = LINE) -> RoundedRectangle:
    return RoundedRectangle(corner_radius=0.14, width=width, height=height, fill_color=CARD,
                            fill_opacity=1, stroke_color=stroke, stroke_width=2)


def labelled_box(title: str, subtitle: str, *, width: float, height: float, title_color: str = TEXT,
                 title_cap: float = CAP_LABEL):
    frame = box(width, height)
    lines = VGroup(text(title, title_cap, color=title_color, bold=True),
                   text(subtitle, CAP_SMALL, color=MUTED)).arrange(DOWN, buff=0.15)
    fit(lines, width - 0.3).move_to(frame.get_center())
    return VGroup(frame, lines)


def event_card(title: str, detail: str, accent: str, width: float = 6.3):
    lines = VGroup(text(title, CAP_CARD, bold=True), text(detail, CAP_SMALL, color=MUTED))
    lines.arrange(DOWN, aligned_edge=LEFT, buff=0.16)
    fit(lines, width - 0.75)
    frame = box(width, lines.height + 0.36)
    stripe = Rectangle(width=0.09, height=frame.height - 0.24, fill_color=accent, fill_opacity=1,
                       stroke_width=0).move_to(frame.get_left() + RIGHT * 0.25)
    lines.next_to(stripe, RIGHT, buff=0.24)
    return VGroup(frame, stripe, lines)


def band_of(score: float):
    return next(b for b in BANDS if b[0] <= score < b[1])


class DaybreakFlow(Scene):
    def construct(self):
        # -- network: protected AP, four clients, the sensor ------------------------------------
        client_ys = (2.55, 1.9, 1.25, 0.6)
        ap = labelled_box("Protected AP", "ExampleSSID", width=2.2, height=1.0)
        ap.move_to([-5.15, sum(client_ys) / len(client_ys), 0])
        clients = VGroup(*[Circle(radius=0.22, fill_color=CARD, fill_opacity=1, stroke_color=TEXT,
                                  stroke_width=3).move_to([-2.45, y, 0]) for y in client_ys])
        clients_label = text("Clients", CAP_SMALL, color=MUTED)
        clients_label.next_to(clients, RIGHT, buff=0.22)
        links = VGroup(*[Line(ap.get_right(), c.get_left(), stroke_width=4, color=OK) for c in clients])
        sensor = labelled_box("Sensor", "receive-only · metadata only", width=3.6, height=1.0)
        sensor.move_to([-3.75, -0.7, 0])

        # -- Daybreak: correlation engine and risk meter ----------------------------------------
        engine = labelled_box("Daybreak", "Correlation Engine", width=4.6, height=1.2, title_color=ACCENT,
                              title_cap=CAP_ENGINE)
        engine.move_to([3.85, 1.55, 0])
        feed = Line(sensor.get_right() + RIGHT * 0.1, engine.get_left() + LEFT * 0.1, stroke_width=2, color=LINE)

        bar_width, bar_left, bar_y = 4.6, 3.85 - 2.3, 0.05
        segments = VGroup(*[Rectangle(width=bar_width * (min(hi, 100) - lo) / 100, height=0.26, stroke_width=0,
                                      fill_color=color, fill_opacity=0.22) for lo, hi, _, color in BANDS])
        segments.arrange(RIGHT, buff=0).move_to([3.85, bar_y, 0])
        meter_label = text("Risk score", CAP_SMALL, color=MUTED).next_to(segments, UP, buff=0.22)
        meter_label.align_to(segments, LEFT)

        score = ValueTracker(0)
        shown = ValueTracker(0)  # opacity of the number and the band label

        def fill():
            value = score.get_value()
            width = max(bar_width * value / 100, 0.001)
            rect = Rectangle(width=width, height=0.26, stroke_width=0, fill_color=band_of(value)[3],
                             fill_opacity=1 if value > 0.5 else 0)
            return rect.move_to([bar_left + width / 2, bar_y, 0])

        def reading():
            value = score.get_value()
            _, _, name, color = band_of(value)
            row = VGroup(text(name, CAP_BAND, color=color, bold=True),
                         text(f"{round(value)}", CAP_SCORE, color=color, bold=True))
            row.arrange(RIGHT, buff=0.2, aligned_edge=DOWN)
            row.next_to(segments, UP, buff=0.2).align_to(segments, RIGHT)
            return row.set_opacity(shown.get_value())

        meter_fill, meter_reading = always_redraw(fill), always_redraw(reading)

        def component(label: str):
            return text(label, CAP_COMPONENT, color=TEXT).next_to(segments, DOWN, buff=0.24).align_to(segments, LEFT)

        tag = text("synthetic example data", CAP_TAG, color=MUTED).to_corner(RIGHT + UP, buff=0.42)

        # -- captions -----------------------------------------------------------------------------
        captions = [
            "Clients connected to the protected AP",
            "A deauthentication burst disconnects them",
            "The clients reconnect",
            "...and re-authenticate (EAPOL)",
            "Daybreak correlates both observations",
            "The risk score adds up, signal by signal",
            "One explained alert",
        ]

        def caption(n: int):
            row = VGroup(text(str(n), CAP_CAPTION, color=ACCENT, bold=True), text(captions[n - 1], CAP_CAPTION))
            row.arrange(RIGHT, buff=0.24)
            return row.to_corner(LEFT + UP, buff=0.42)

        current = caption(1)

        def step(n: int):
            nonlocal current
            new = caption(n)
            old, current = current, new
            return Succession(FadeOut(old), FadeIn(new))  # one after the other: no overlapping text

        # -- observed frames: dots from the links into the sensor (inbound only) -------------------
        def observed(color: str):
            dots = VGroup(*[Dot(links[i % 4].point_from_proportion(0.4 + 0.2 * (i // 4)), radius=0.065,
                                color=color) for i in range(8)])
            target = sensor.get_top() + DOWN * 0.08
            return dots, LaggedStart(*[d.animate.move_to(target).set_opacity(0.0) for d in dots], lag_ratio=0.1)

        static = VGroup(links, ap, clients, clients_label, sensor, feed, engine, segments, meter_label, tag)
        self.add(static, meter_fill, meter_reading, current)

        # 1. normal operation
        self.wait(0.9)

        # 2. deauthentication burst: the clients are disconnected, the sensor hears the frames
        card_deauth = event_card("Deauthentication burst detected", "11 frames in 5 s · 4 clients affected", DEAUTH)
        card_deauth.move_to([-3.6, -2.0, 0])
        self.play(step(2), links.animate.set_stroke(color=DEAUTH, opacity=0.35),
                  clients.animate.set_stroke(color=MUTED), run_time=0.6)
        dots, fall = observed(DEAUTH)
        self.add(dots)
        self.play(fall, run_time=0.9)
        self.remove(dots)
        self.play(FadeIn(card_deauth, shift=UP * 0.15), self.flash(sensor[0], DEAUTH), run_time=0.6)
        self.wait(0.3)

        # 3. the clients reconnect
        self.play(step(3), links.animate.set_stroke(color=OK, opacity=1), clients.animate.set_stroke(color=TEXT),
                  run_time=0.7)

        # 4. ...and re-authenticate: EAPOL message numbers only
        card_eapol = event_card("EAPOL reauthentication surge", "4 clients re-authenticate in 60 s", EAPOL)
        card_eapol.move_to([-3.6, -3.12, 0])
        dots, fall = observed(EAPOL)
        self.add(dots)
        self.play(step(4), fall, run_time=0.9)
        self.remove(dots)
        self.play(FadeIn(card_eapol, shift=UP * 0.15), self.flash(sensor[0], EAPOL), run_time=0.5)
        self.wait(0.3)

        # 5. both observations go into the correlation engine
        self.play(step(5), feed.animate.set_stroke(color=ACCENT, width=3),
                  LaggedStart(*[c.animate.scale(0.18).move_to(engine.get_center()).set_opacity(0)
                                for c in (card_deauth, card_eapol)], lag_ratio=0.25),
                  engine[0].animate.set_stroke(color=ACCENT, width=3), run_time=1.2)
        self.remove(card_deauth, card_eapol)

        # 6. the risk score adds up through the bands, one listed component at a time
        line = None
        for i, (value, label) in enumerate(SCORE_STEPS):
            new = component(label)
            swap = [FadeIn(new, shift=UP * 0.1)] + ([FadeOut(line)] if line is not None else [])
            extra = [step(6), shown.animate.set_value(1)] if i == 0 else []
            self.play(score.animate.set_value(value), *swap, *extra, run_time=0.5, rate_func=smooth)
            line = new
            self.wait(0.3)  # time to read the component

        # 7. the alert
        alert = self.alert_card()
        self.play(step(7), FadeIn(alert, shift=UP * 0.15), run_time=0.7)
        self.wait(0.4)

        # 8. what Daybreak never does
        footer = VGroup(text("Passive defensive monitoring only", CAP_FOOTER, bold=True),
                        text("No packet injection / No credential cracking", CAP_FOOTER, color=MUTED))
        footer.arrange(DOWN, buff=0.16).move_to([0, -3.42, 0])
        self.play(FadeIn(footer, shift=UP * 0.1), run_time=0.7)
        self.wait(1.9)

        # back to the first frame, so the GIF loops without a jump
        self.play(step(1), FadeOut(alert), FadeOut(footer), FadeOut(line), shown.animate.set_value(0),
                  score.animate.set_value(0), feed.animate.set_stroke(color=LINE, width=2),
                  engine[0].animate.set_stroke(color=LINE, width=2), run_time=0.6, rate_func=linear)
        # Manim renders a play() up to, not including, its end state: show that state briefly
        self.wait(0.2)

    @staticmethod
    def flash(frame, color: str):
        """Outline of ``frame`` briefly in ``color`` (the fill stays: no full-box flash)."""
        return frame.animate(rate_func=there_and_back).set_stroke(color=color, width=4)

    def alert_card(self):
        severity = VGroup(text("HIGH", CAP_ALERT, color=HIGH, bold=True), text("/", CAP_ALERT, color=MUTED),
                          text("CRITICAL", CAP_ALERT, color=CRITICAL, bold=True).set_opacity(0.7))
        severity.arrange(RIGHT, buff=0.22)
        kind = text("POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT", CAP_ALERT_TYPE, mono=True)
        note = text("this example: 72 HIGH  ·  README demo replay: 95 CRITICAL", CAP_SMALL, color=MUTED)
        lines = VGroup(severity, kind, note).arrange(DOWN, buff=0.16)
        fit(lines, 10.4)
        frame = box(11.0, lines.height + 0.34, stroke=HIGH)
        return VGroup(frame, lines.move_to(frame.get_center())).move_to([0, -2.18, 0])
