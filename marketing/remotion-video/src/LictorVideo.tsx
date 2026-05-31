import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion';

const FPS = 30;

// Text events with timing in seconds
type TextEvent = {
  text: string;
  size: number;
  color: string;
  yOffset: number;
  start: number;
  duration: number;
};

const TEXTS: TextEvent[] = [
  // SCENE 1 — HOOK (0–8s)
  { text: '36 MILLION',          size: 200, color: '#FFD700', yOffset: -250, start: 1.0, duration: 3.0 },
  { text: 'WEBSITES',            size: 140, color: '#FFFFFF', yOffset:    0, start: 1.6, duration: 2.4 },
  { text: '4 DAYS',              size: 160, color: '#00E5FF', yOffset: -150, start: 4.5, duration: 2.4 },
  { text: '1 PERSON',            size: 160, color: '#FF6B9D', yOffset:   80, start: 4.9, duration: 2.0 },
  { text: "HERE'S WHAT I FOUND", size:  90, color: '#FFFFFF', yOffset:  320, start: 6.5, duration: 1.5 },
  // SCENE 2 — REVEAL (8–16s)
  { text: 'A LEAKED KEY',        size: 130, color: '#FFD700', yOffset: -100, start:  8.5, duration: 1.4 },
  { text: 'A FORGOTTEN DOOR',    size: 130, color: '#00E5FF', yOffset: -100, start: 10.0, duration: 1.4 },
  { text: 'AN OPEN VAULT',       size: 130, color: '#FFB347', yOffset: -100, start: 11.5, duration: 1.4 },
  { text: 'A POISONED CHAIN',    size: 130, color: '#FF4757', yOffset: -100, start: 13.0, duration: 1.4 },
  { text: "AT THE WORLD'S",      size:  95, color: '#FFFFFF', yOffset: -120, start: 14.5, duration: 1.5 },
  { text: 'BIGGEST COMPANIES',   size: 120, color: '#FFFFFF', yOffset:   20, start: 14.5, duration: 1.5 },
  // SCENE 3 — CALL (16–24s)
  { text: 'REPORTED PRIVATELY',  size: 100, color: '#00FF94', yOffset: -150, start: 16.5, duration: 2.0 },
  { text: 'ZERO NAMES PUBLISHED', size: 85, color: '#FFFFFF', yOffset:    0, start: 17.0, duration: 2.0 },
  { text: 'lictor-ai.com',       size: 170, color: '#FFD700', yOffset:  -50, start: 19.5, duration: 4.0 },
  { text: 'OPEN SOURCE',         size:  70, color: '#FFFFFF', yOffset:  100, start: 20.0, duration: 4.0 },
  { text: 'FREE FOREVER',        size:  70, color: '#FFFFFF', yOffset:  170, start: 20.3, duration: 3.7 },
  { text: 'STAND ON THE LINE',   size:  95, color: '#00E5FF', yOffset:  320, start: 21.0, duration: 3.0 },
];

// Background colors per scene
const bgColor = (t: number): string => {
  if (t < 7.5) return '#0B1729';
  if (t < 8.5) {
    const a = (t - 7.5) / 1.0;
    return blend('#0B1729', '#1A0B29', a);
  }
  if (t < 15.5) return '#1A0B29';
  if (t < 16.5) {
    const a = (t - 15.5) / 1.0;
    return blend('#1A0B29', '#2B1810', a);
  }
  return '#2B1810';
};

function blend(c1: string, c2: string, a: number): string {
  const r1 = parseInt(c1.slice(1, 3), 16);
  const g1 = parseInt(c1.slice(3, 5), 16);
  const b1 = parseInt(c1.slice(5, 7), 16);
  const r2 = parseInt(c2.slice(1, 3), 16);
  const g2 = parseInt(c2.slice(3, 5), 16);
  const b2 = parseInt(c2.slice(5, 7), 16);
  const r = Math.round(r1 * (1 - a) + r2 * a);
  const g = Math.round(g1 * (1 - a) + g2 * a);
  const b = Math.round(b1 * (1 - a) + b2 * a);
  return `rgb(${r}, ${g}, ${b})`;
}

// Animated particle field (background depth)
const Particles: React.FC = () => {
  const frame = useCurrentFrame();
  const { width, height } = useVideoConfig();
  // 60 deterministic particles seeded by index
  const particles = Array.from({ length: 60 }, (_, i) => {
    const seed = i * 12.9898;
    const x = ((Math.sin(seed) * 43758.5453) % 1 + 1) % 1 * width;
    const baseY = ((Math.sin(seed * 2) * 43758.5453) % 1 + 1) % 1 * height;
    const speed = 0.3 + ((Math.sin(seed * 3) * 43758.5453) % 1 + 1) % 1 * 1.5;
    const y = (baseY + frame * speed) % (height + 50) - 25;
    const size = 1 + ((Math.sin(seed * 5) * 43758.5453) % 1 + 1) % 1 * 3;
    const opacity = 0.2 + ((Math.sin(seed * 7) * 43758.5453) % 1 + 1) % 1 * 0.5;
    const hue = 200 + ((Math.sin(seed * 11) * 43758.5453) % 1 + 1) % 1 * 60;
    return { x, y, size, opacity, hue, key: i };
  });
  return (
    <>
      {particles.map(p => (
        <div
          key={p.key}
          style={{
            position: 'absolute',
            left: p.x,
            top: p.y,
            width: p.size * 2,
            height: p.size * 2,
            borderRadius: '50%',
            background: `hsl(${p.hue}, 80%, 70%)`,
            opacity: p.opacity,
            boxShadow: `0 0 ${p.size * 4}px hsl(${p.hue}, 100%, 60%)`,
          }}
        />
      ))}
    </>
  );
};

const AnimatedText: React.FC<{ event: TextEvent }> = ({ event }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const t = frame / fps;
  const startFrame = event.start * fps;
  const endFrame = (event.start + event.duration) * fps;
  if (frame < startFrame || frame >= endFrame) return null;

  // Spring-based scale on appear
  const appearProgress = spring({
    frame: frame - startFrame,
    fps,
    config: { damping: 12, mass: 0.8 },
  });
  const scale = 0.7 + 0.3 * appearProgress;

  // Linear fade-in / fade-out
  const fadeIn = Math.min(1, (frame - startFrame) / (fps * 0.25));
  const fadeOut = Math.min(1, (endFrame - frame) / (fps * 0.4));
  const opacity = Math.max(0, Math.min(fadeIn, fadeOut));

  // Subtle vertical drift
  const drift = interpolate(frame - startFrame, [0, endFrame - startFrame], [0, -10]);

  return (
    <div
      style={{
        position: 'absolute',
        left: 0,
        right: 0,
        top: '50%',
        transform: `translateY(calc(-50% + ${event.yOffset + drift}px)) scale(${scale})`,
        textAlign: 'center',
        fontFamily: '"Helvetica Neue", Helvetica, Arial, sans-serif',
        fontWeight: 900,
        fontSize: event.size,
        color: event.color,
        opacity,
        letterSpacing: '-0.02em',
        textShadow: `0 0 30px ${event.color}66, 0 4px 12px rgba(0,0,0,0.6)`,
        WebkitTextStroke: '1px rgba(0,0,0,0.4)',
      }}
    >
      {event.text}
    </div>
  );
};

export const LictorVideo: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps, width, height } = useVideoConfig();
  const t = frame / fps;
  const bg = bgColor(t);

  // Subtle camera zoom over the whole video for life
  const zoom = 1 + Math.sin(t * 0.3) * 0.02;

  return (
    <AbsoluteFill style={{ background: bg, overflow: 'hidden' }}>
      {/* Radial gradient overlay for depth */}
      <AbsoluteFill
        style={{
          background: `radial-gradient(circle at 50% 50%, transparent 0%, rgba(0,0,0,0.4) 100%)`,
          transform: `scale(${zoom})`,
        }}
      />
      {/* Particle field */}
      <Particles />
      {/* Text overlays */}
      {TEXTS.map((event, i) => (
        <AnimatedText key={i} event={event} />
      ))}
    </AbsoluteFill>
  );
};
