import { useEffect, useRef } from "react";

interface Props {
  /** "wave": a multi-band scrolling trace, like an oscilloscope reading
   *  packet throughput. "radar": a sweeping radar circle with blips. */
  variant: "wave" | "radar";
  className?: string;
}

const ACCENT = "#d3a03c"; // --accent
const ACCENT_2 = "#49c9c2"; // --accent-2
const GRID = "rgba(238, 241, 251, 0.06)";

/**
 * A self-contained generative graphic standing in for the "AI image"
 * hero art this project has no way to generate — an instrument reading
 * fits the subject better than a stock illustration would anyway, and it
 * animates, which a static image can't.
 */
export function SignalScope({ variant, className }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    let width = 0;
    let height = 0;

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      width = rect.width;
      height = rect.height;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);

    let raf = 0;
    let t = 0;

    const drawGrid = () => {
      ctx.strokeStyle = GRID;
      ctx.lineWidth = 1;
      const step = 28;
      for (let x = 0; x < width; x += step) {
        ctx.beginPath();
        ctx.moveTo(x + 0.5, 0);
        ctx.lineTo(x + 0.5, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += step) {
        ctx.beginPath();
        ctx.moveTo(0, y + 0.5);
        ctx.lineTo(width, y + 0.5);
        ctx.stroke();
      }
    };

    const drawWave = () => {
      ctx.clearRect(0, 0, width, height);
      drawGrid();

      const bands: { color: string; amp: number; freq: number; speed: number; offset: number }[] =
        [
          { color: ACCENT, amp: height * 0.16, freq: 0.028, speed: 1, offset: height * 0.38 },
          { color: ACCENT_2, amp: height * 0.1, freq: 0.045, speed: -1.4, offset: height * 0.68 },
        ];

      for (const band of bands) {
        ctx.beginPath();
        ctx.strokeStyle = band.color;
        ctx.lineWidth = 2;
        ctx.shadowColor = band.color;
        ctx.shadowBlur = 8;
        for (let x = 0; x <= width; x += 3) {
          const spike =
            Math.sin(x * band.freq + t * band.speed) *
            (0.6 + 0.4 * Math.sin(x * 0.01 + t * 0.3));
          const y = band.offset + spike * band.amp;
          if (x === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }
        ctx.stroke();
        ctx.shadowBlur = 0;
      }
    };

    const drawRadar = () => {
      ctx.clearRect(0, 0, width, height);
      const cx = width / 2;
      const cy = height / 2;
      const r = Math.min(width, height) / 2 - 6;

      ctx.strokeStyle = GRID;
      ctx.lineWidth = 1;
      for (const ring of [0.35, 0.65, 1]) {
        ctx.beginPath();
        ctx.arc(cx, cy, r * ring, 0, Math.PI * 2);
        ctx.stroke();
      }
      ctx.beginPath();
      ctx.moveTo(cx - r, cy);
      ctx.lineTo(cx + r, cy);
      ctx.moveTo(cx, cy - r);
      ctx.lineTo(cx, cy + r);
      ctx.stroke();

      const sweep = t * 0.9;
      const grad = ctx.createConicGradient
        ? ctx.createConicGradient(sweep - Math.PI / 2, cx, cy)
        : null;
      if (grad) {
        grad.addColorStop(0, "rgba(211, 160, 60, 0)");
        grad.addColorStop(0.08, "rgba(211, 160, 60, 0.35)");
        grad.addColorStop(0.16, "rgba(211, 160, 60, 0)");
        grad.addColorStop(1, "rgba(211, 160, 60, 0)");
        ctx.save();
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.clip();
        ctx.fillStyle = grad;
        ctx.fillRect(cx - r, cy - r, r * 2, r * 2);
        ctx.restore();
      }

      ctx.strokeStyle = ACCENT;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + Math.cos(sweep) * r, cy + Math.sin(sweep) * r);
      ctx.stroke();

      const blips = [
        { a: 0.6, d: 0.75 },
        { a: 2.4, d: 0.45 },
        { a: 4.1, d: 0.85 },
      ];
      for (const b of blips) {
        const bx = cx + Math.cos(b.a) * r * b.d;
        const by = cy + Math.sin(b.a) * r * b.d;
        const dist = ((sweep - b.a) % (Math.PI * 2) + Math.PI * 2) % (Math.PI * 2);
        const glow = Math.max(0, 1 - dist / 1.2);
        if (glow <= 0.02) continue;
        ctx.beginPath();
        ctx.fillStyle = ACCENT_2;
        ctx.globalAlpha = 0.4 + glow * 0.6;
        ctx.arc(bx, by, 2.5 + glow * 2.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.globalAlpha = 1;
      }
    };

    const draw = variant === "wave" ? drawWave : drawRadar;

    if (reduceMotion) {
      draw();
    } else {
      const loop = () => {
        t += 0.02;
        draw();
        raf = requestAnimationFrame(loop);
      };
      raf = requestAnimationFrame(loop);
    }

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, [variant]);

  return <canvas ref={canvasRef} className={className} aria-hidden="true" />;
}
