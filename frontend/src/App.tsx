import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { Fragment, type AnchorHTMLAttributes, type CSSProperties, type MouseEvent, type ReactNode, useEffect, useLayoutEffect, useRef, useState } from "react";
import { copyAgentQuickTestPrompt } from "./agent-quick-test";
import {
  API_ENDPOINTS,
  MAX_DEPENDENCIES,
  buildAgentInspectionPrompt,
  buildRequest,
  copyText,
  isEndpointId,
  validateInspection,
  type BuilderValues,
  type EndpointId,
  type InspectionInput,
  type PackageInput,
  type RepositoryInput,
} from "./agent-inspection-prompt";

gsap.registerPlugin(ScrollTrigger);

type Theme = "light" | "dark";

function readThemePreference(): Theme {
  try {
    return window.localStorage.getItem("omni-theme") === "dark" ? "dark" : "light";
  } catch {
    return "light";
  }
}

function persistThemePreference(theme: Theme): void {
  try {
    window.localStorage.setItem("omni-theme", theme);
  } catch {
    // Theme persistence is optional when storage is unavailable.
  }
}

type RouteLocation = { pathname: string; search: string; hash: string };
type ViewTransitionDocument = { startViewTransition?: (update: () => void) => { finished: Promise<void> } };

function readRouteLocation(): RouteLocation {
  return { pathname: window.location.pathname, search: window.location.search, hash: window.location.hash };
}

function updateRouteLocation(setLocation: (location: RouteLocation) => void, shouldTransition: boolean): void {
  const commit = () => setLocation(readRouteLocation());
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const transitionDocument = document as unknown as ViewTransitionDocument;
  if (shouldTransition && typeof transitionDocument.startViewTransition === "function" && !reduceMotion) transitionDocument.startViewTransition(commit);
  else commit();
}

function scrollToRouteTarget(targetId: string): void {
  const target = targetId ? document.getElementById(targetId) : null;
  const top = target ? Math.max(0, window.scrollY + target.getBoundingClientRect().top - 112) : 0;
  window.scrollTo({ top, left: 0, behavior: target && !window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "smooth" : "auto" });
}

function navigateInternal(href: string): void {
  const target = new URL(href, window.location.href);
  if (target.origin !== window.location.origin) return;
  const next = `${target.pathname}${target.search}${target.hash}`;
  const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  if (next === current) return;
  window.history.pushState(null, "", next);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function InternalLink({ href, onClick, ...props }: AnchorHTMLAttributes<HTMLAnchorElement>) {
  const handleClick = (event: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(event);
    if (event.defaultPrevented || !href || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.currentTarget.target === "_blank" || event.currentTarget.hasAttribute("download")) return;
    const target = new URL(href, window.location.href);
    if (target.origin !== window.location.origin) return;
    event.preventDefault();
    navigateInternal(href);
  };
  return <a {...props} href={href} onClick={handleClick} />;
}

const ecosystemLogos = [
  { key: "circle", label: "CIRCLE", src: "/circle-gradient.png", kind: "image" as const },
  { key: "arc", label: "ARC", src: "/arc-clean.png", kind: "mask" as const },
  { key: "mcp", label: "MCP", src: "/mcp-mask.png", kind: "mask" as const },
  { key: "x402", label: "X402", src: "/x402-clean.png", kind: "mask" as const },
];

const INITIAL_BUILDER_VALUES: BuilderValues = {
  package: { ecosystem: "npm", name: "express", version: "5.2.1" },
  repo: { owner: "expressjs", repo: "express" },
  dependencies: [{ id: 1, ecosystem: "npm", name: "express", version: "5.2.1" }],
  preflight: { url: "" },
};

type ApiPreviewSegment = { text: string; className?: string };
type ApiPreviewBlock = { kind: "line"; segments: readonly ApiPreviewSegment[] } | { kind: "divider" };

const API_PREVIEW_BLOCKS: readonly ApiPreviewBlock[] = [
  { kind: "line", segments: [{ text: "GET", className: "syntax-muted" }, { text: " /v1/x402/endpoint/preflight" }] },
  { kind: "line", segments: [{ text: "Accept: application/json", className: "syntax-muted" }] },
  { kind: "line", segments: [{ text: "Idempotency-Key: UUID v4", className: "syntax-muted" }] },
  { kind: "divider" },
  { kind: "line", segments: [{ text: "recommendation", className: "syntax-key" }, { text: ": " }, { text: "advisory", className: "syntax-value" }] },
  { kind: "line", segments: [{ text: "evidenceCoverage", className: "syntax-key" }, { text: ": " }, { text: "source-derived", className: "syntax-value" }] },
  { kind: "line", segments: [{ text: "policyVersion", className: "syntax-key" }, { text: ": " }, { text: "deterministic", className: "syntax-value" }] },
];

const API_PREVIEW_TEXT_LENGTH = API_PREVIEW_BLOCKS.reduce((total, block) => total + (block.kind === "line" ? block.segments.reduce((lineTotal, segment) => lineTotal + segment.text.length, 0) : 0), 0);
const API_PREVIEW_TYPE_DELAY_MS = 28;
const API_PREVIEW_HOLD_MS = 3000;
const API_PREVIEW_BLANK_MS = 450;

type DocsArticleId = "overview" | "quickstart" | "package" | "repository" | "dependencies" | "preflight" | "results" | "evidence" | "payment" | "security" | "architecture" | "wallet";
type DocsNavGroup = { label: string; items: readonly { href: string; label: string }[] };
type DocsSection = { id: string; title: string; content: ReactNode };
type DocsArticle = { label: string; title: string; intro: string; actions?: ReactNode; sections: readonly DocsSection[] };

const DOCS_NAV_GROUPS: readonly DocsNavGroup[] = [
  { label: "Start here", items: [{ href: "/docs", label: "What OMNI does" }, { href: "/docs/quickstart", label: "Quickstart" }] },
  { label: "API reference", items: [{ href: "/docs/package-risk", label: "Package risk" }, { href: "/docs/repository-risk", label: "Repository risk" }, { href: "/docs/dependency-risk", label: "Dependency risk" }, { href: "/docs/x402-preflight", label: "x402 preflight" }] },
  { label: "Understand a result", items: [{ href: "/docs/results", label: "Assessment fields" }, { href: "/docs/evidence", label: "Evidence and source errors" }] },
  { label: "Payment and safety", items: [{ href: "/docs/x402-payment", label: "The x402 flow" }, { href: "/docs/security", label: "Safety and failures" }] },
  { label: "Project reference", items: [{ href: "/docs/architecture", label: "Architecture" }, { href: "/docs/agent-wallet", label: "Agent wallet guide" }] },
];

const DOCS_ARTICLE_PATHS: Readonly<Record<string, DocsArticleId>> = {
  "/docs": "overview",
  "/docs/quickstart": "quickstart",
  "/docs/package-risk": "package",
  "/docs/repository-risk": "repository",
  "/docs/dependency-risk": "dependencies",
  "/docs/x402-preflight": "preflight",
  "/docs/results": "results",
  "/docs/evidence": "evidence",
  "/docs/x402-payment": "payment",
  "/docs/security": "security",
  "/docs/architecture": "architecture",
  "/docs/agent-wallet": "wallet",
};

const DOCS_LEGACY_HASH_PATHS: Readonly<Record<string, string>> = {
  "docs-overview": "/docs",
  "docs-quickstart": "/docs/quickstart",
  "docs-endpoints": "/docs/package-risk",
  "docs-results": "/docs/results",
  "docs-evidence": "/docs/evidence",
  "docs-payment": "/docs/x402-payment",
  "docs-reference": "/docs/architecture",
};

function ApiPreview() {
  const [typedChars, setTypedChars] = useState(0);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setTypedChars(API_PREVIEW_TEXT_LENGTH);
      return;
    }

    let current = 0;
    let typingTimer: number | null = null;
    let holdTimer: number | null = null;
    let blankTimer: number | null = null;
    const typeNext = () => {
      current += 1;
      setTypedChars(current);
      if (current < API_PREVIEW_TEXT_LENGTH) {
        typingTimer = window.setTimeout(typeNext, API_PREVIEW_TYPE_DELAY_MS);
        return;
      }

      holdTimer = window.setTimeout(() => {
        current = 0;
        setTypedChars(0);
        blankTimer = window.setTimeout(typeNext, API_PREVIEW_BLANK_MS);
      }, API_PREVIEW_HOLD_MS);
    };

    blankTimer = window.setTimeout(typeNext, API_PREVIEW_BLANK_MS);
    return () => {
      if (typingTimer !== null) window.clearTimeout(typingTimer);
      if (holdTimer !== null) window.clearTimeout(holdTimer);
      if (blankTimer !== null) window.clearTimeout(blankTimer);
    };
  }, []);

  let blockStart = 0;
  return (
    <div className="api-window__body">
      {API_PREVIEW_BLOCKS.map((block, blockIndex) => {
        if (block.kind === "divider") return typedChars >= blockStart ? <div className="api-divider" key={`divider-${blockIndex}`} /> : null;

        const lineStart = blockStart;
        const lineLength = block.segments.reduce((total, segment) => total + segment.text.length, 0);
        blockStart += lineLength;
        let segmentStart = lineStart;
        const segments = block.segments.map((segment, segmentIndex) => {
          const visibleLength = Math.max(0, Math.min(segment.text.length, typedChars - segmentStart));
          const rendered = visibleLength > 0 ? <span className={segment.className} key={`${blockIndex}-${segmentIndex}`}>{segment.text.slice(0, visibleLength)}</span> : null;
          segmentStart += segment.text.length;
          return rendered;
        });

        return typedChars > lineStart ? <p key={`line-${blockIndex}`}>{segments}</p> : null;
      })}
      {typedChars > 0 ? <div className="api-cursor" /> : null}
    </div>
  );
}

function Logo({ size = "small" }: { size?: "small" | "large" }) {
  return (
    <span className={`logo-lockup logo-lockup--${size}`}>
      <img className="brand-mark" src="/omni-logo-clean.png" alt="OMNI logo" />
    </span>
  );
}

function Magnetic({ children, strength = 0.22 }: { children: ReactNode; strength?: number }) {
  const ref = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    const element = ref.current;
    if (!element) return;

    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const finePointer = window.matchMedia("(hover: hover) and (pointer: fine)").matches;
    if (reduceMotion || !finePointer) return;

    const xTo = gsap.quickTo(element, "x", { duration: 0.36, ease: "power3.out" });
    const yTo = gsap.quickTo(element, "y", { duration: 0.36, ease: "power3.out" });
    const onMove = (event: globalThis.PointerEvent) => {
      const bounds = element.getBoundingClientRect();
      xTo((event.clientX - bounds.left - bounds.width / 2) * strength);
      yTo((event.clientY - bounds.top - bounds.height / 2) * strength);
    };
    const onLeave = () => {
      xTo(0);
      yTo(0);
    };

    element.addEventListener("pointermove", onMove);
    element.addEventListener("pointerleave", onLeave);
    return () => {
      element.removeEventListener("pointermove", onMove);
      element.removeEventListener("pointerleave", onLeave);
      gsap.killTweensOf(element);
      gsap.set(element, { clearProps: "transform" });
    };
  }, [strength]);

  return <span ref={ref} className="magnetic-wrap">{children}</span>;
}

function CopyIcon({ checked = false }: { checked?: boolean }) {
  return checked ? (
    <svg viewBox="0 0 16 16" aria-hidden="true"><path d="m3.2 8.2 3.1 3.1 6.5-6.6" /></svg>
  ) : (
    <svg viewBox="0 0 16 16" aria-hidden="true"><rect x="5.2" y="5.2" width="7.1" height="7.1" rx="1.2" /><path d="M10.1 5.2V3.7c0-.7-.5-1.2-1.2-1.2H4.1c-.7 0-1.2.5-1.2 1.2v4.8c0 .7.5 1.2 1.2 1.2h1.1" /></svg>
  );
}

function ThemeToggle({ theme, onChange }: { theme: Theme; onChange: () => void }) {
  return (
    <Magnetic strength={0.16}>
      <button className="theme-toggle" type="button" onClick={onChange} aria-label={`Switch to ${theme === "light" ? "dark" : "light"} mode`}>
        <span className="theme-toggle__orb" aria-hidden="true" />
        <span>{theme === "light" ? "Light" : "Dark"}</span>
      </button>
    </Magnetic>
  );
}

type QuickTestCopyState = "idle" | "copied" | "failed";

function AgentQuickTestButton() {
  const [state, setState] = useState<QuickTestCopyState>("idle");
  const resetRef = useRef<number | null>(null);

  useEffect(() => () => {
    if (resetRef.current !== null) window.clearTimeout(resetRef.current);
  }, []);

  const copyPrompt = async () => {
    try {
      await copyAgentQuickTestPrompt();
      setState("copied");
    } catch {
      setState("failed");
    }
    if (resetRef.current !== null) window.clearTimeout(resetRef.current);
    resetRef.current = window.setTimeout(() => setState("idle"), 2600);
  };

  const label = state === "copied"
    ? "✓ PROMPT COPIED. PASTE TO YOUR AGENT"
    : state === "failed"
      ? "COPY FAILED — RETRY"
      : "TRY WITH YOUR AGENT";
  return <button className="button button--dark agent-quick-test" type="button" onClick={() => void copyPrompt()}>{label}</button>;
}

function OrbitField({ className = "" }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const hostRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const host = hostRef.current;
    if (!canvas || !host) return;

    const context = canvas.getContext("2d");
    if (!context) return;

    let frame = 0;
    let lastDrawAt = 0;
    let animationFrame = 0;
    let active = true;
    let width = 0;
    let height = 0;
    const pointer = { x: 0, y: 0, targetX: 0, targetY: 0 };
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const particleCount = window.innerWidth < 720 ? 110 : window.innerWidth < 1200 ? 145 : 180;
    const particles = Array.from({ length: particleCount }, (_, index) => ({
      offset: -1.35 + ((index * 47) % 100) / 100 * 2.7,
      depth: ((index * 37) % 100) / 100,
      speed: 0.00115 + ((index * 17) % 9) * 0.00014,
      phase: (index * 0.618) % (Math.PI * 2),
      length: 0.07 + ((index * 23) % 100) / 100 * 0.16,
      bend: -0.5 + ((index * 29) % 100) / 100,
      width: index % 13 === 0 ? 1.08 : index % 5 === 0 ? 0.82 : 0.46 + (index % 4) * 0.1,
      dot: index % 4 === 0,
    }));

    const resize = () => {
      const bounds = host.getBoundingClientRect();
      const pixelRatio = Math.min(window.devicePixelRatio || 1, window.innerWidth < 720 ? 1.1 : 1.25);
      width = bounds.width;
      height = bounds.height;
      canvas.width = Math.floor(width * pixelRatio);
      canvas.height = Math.floor(height * pixelRatio);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
    };

    const draw = () => {
      context.clearRect(0, 0, width, height);
      pointer.x += (pointer.targetX - pointer.x) * 0.035;
      pointer.y += (pointer.targetY - pointer.y) * 0.035;
      const centerX = width * 0.5 + pointer.x * 28;
      const centerY = height * 0.04 + pointer.y * 18;
      const dark = document.documentElement.dataset.theme === "dark";
      const streakColors = dark ? ["119, 101, 255", "219, 191, 255", "92, 144, 255"] : ["32, 35, 45", "77, 80, 92"];

      context.save();
      context.globalCompositeOperation = dark ? "screen" : "multiply";
      for (const particle of particles) {
        const progress = (particle.depth + frame * particle.speed) % 1.28;
        if (progress < 0.015) continue;
        const endT = Math.min(progress, 1.12);
        const startT = Math.max(0.018, endT - particle.length * (0.52 + endT * 0.44));
        const point = (t: number) => {
          const spread = 0.42 + t * 0.86;
          const sway = Math.sin(particle.phase + t * 5.4 + frame * 0.00035) * particle.bend * width * 0.035 * t;
          return {
            x: centerX + particle.offset * width * 0.48 * spread + sway,
            y: centerY + t * height * 1.06,
          };
        };
        const start = point(startT);
        const end = point(endT);
        const middle = point((startT + endT) * 0.5);
        const controlX = middle.x + Math.sin(particle.phase + frame * 0.0005) * width * 0.012 * endT;
        const controlY = middle.y - height * 0.04;
        const alpha = Math.min(0.82, 0.12 + endT * 0.58) * (0.76 + (particle.length / 0.23) * 0.24);

        context.beginPath();
        context.moveTo(start.x, start.y);
        context.quadraticCurveTo(controlX, controlY, end.x, end.y);
        const streakColor = streakColors[Math.floor((particle.phase * 3 + particle.offset) % streakColors.length + streakColors.length) % streakColors.length];
        context.strokeStyle = `rgba(${streakColor}, ${alpha})`;
        context.lineWidth = particle.width * (0.38 + endT * 0.68);
        context.stroke();

        if (particle.dot && endT > 0.18) {
          context.beginPath();
          context.arc(end.x, end.y, particle.width * (0.7 + endT * 0.9), 0, Math.PI * 2);
          context.fillStyle = `rgba(${streakColor}, ${Math.min(0.95, alpha + 0.12)})`;
          context.fill();
        }
      }
      context.restore();
      context.globalAlpha = 1;
    };

    const render = (timestamp = 0) => {
      if (!active || document.hidden) {
        animationFrame = 0;
        return;
      }
      if (!lastDrawAt || timestamp - lastDrawAt >= 32) {
        draw();
        frame += 2;
        lastDrawAt = timestamp;
      }
      if (!reduceMotion) animationFrame = window.requestAnimationFrame(render);
    };
    const onVisibilityChange = () => {
      if (!document.hidden && active && !reduceMotion && animationFrame === 0) animationFrame = window.requestAnimationFrame(render);
    };
    const onPointerMove = (event: PointerEvent) => {
      const bounds = host.getBoundingClientRect();
      pointer.targetX = (event.clientX - bounds.left) / bounds.width - 0.5;
      pointer.targetY = (event.clientY - bounds.top) / bounds.height - 0.5;
    };
    const onPointerLeave = () => {
      pointer.targetX = 0;
      pointer.targetY = 0;
    };
    const observer = new IntersectionObserver(([entry]) => {
      active = entry?.isIntersecting ?? true;
      if (active && !reduceMotion && animationFrame === 0) animationFrame = window.requestAnimationFrame(render);
    }, { threshold: 0.01 });

    resize();
    context.lineCap = "round";
    render();
    observer.observe(host);
    window.addEventListener("resize", resize);
    document.addEventListener("visibilitychange", onVisibilityChange);
    host.addEventListener("pointermove", onPointerMove);
    host.addEventListener("pointerleave", onPointerLeave);

    return () => {
      active = false;
      window.cancelAnimationFrame(animationFrame);
      observer.disconnect();
      window.removeEventListener("resize", resize);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      host.removeEventListener("pointermove", onPointerMove);
      host.removeEventListener("pointerleave", onPointerLeave);
    };
  }, []);

  return <div ref={hostRef} className={`orbit-field ${className}`.trim()} aria-hidden="true"><canvas ref={canvasRef} /></div>;
}

function InterceptorCard() {
  const [phase, setPhase] = useState(0);
  const phases = [
    { label: "Agent request", value: "GET /v1/x402/endpoint/preflight", status: "checking evidence" },
    { label: "OMNI check", value: "software + service + payment", status: "evidence ready" },
    { label: "Assessment", value: "riskScore · recommendation · coverage", status: "policy decides" },
  ];

  useEffect(() => {
    const interval = window.setInterval(() => setPhase((current) => (current + 1) % phases.length), 3700);
    return () => window.clearInterval(interval);
  }, [phases.length]);

  const current = phases[phase];
  return (
    <div className="interceptor-card" aria-label="Illustrative OMNI interception sequence">
      <div className="interceptor-card__topline"><span>LIVE TRUST SEAM</span><span className="signal"><i /> observing</span></div>
      <div className="interceptor-card__action">
        <span className="action-dot" />
        <span>agent://action/0x7E4</span>
        <span className="action-time">00:0{phase + 1}</span>
      </div>
      <div className="scanner-visual">
        <div className="scanner-orbit scanner-orbit--one" />
        <div className="scanner-orbit scanner-orbit--two" />
        <div className="scanner-core"><img src="/omni-logo-clean.png" alt="" /></div>
        <span className="scanner-beam scanner-beam--one" />
        <span className="scanner-beam scanner-beam--two" />
      </div>
      <div className="interceptor-card__state" key={current.label}>
        <span className="eyebrow">{current.label}</span>
        <strong>{current.value}</strong>
        <span className="state-status"><i /> {current.status}</span>
      </div>
      <div className="interceptor-card__footer"><span>advice only</span><span>does not settle payments</span></div>
    </div>
  );
}

function EvidenceShowcase() {
  return (
    <div className="evidence-showcase">
      <div className="evidence-guide" id="supply-chain-evidence">
        <div className="evidence-guide__intro">
          <span className="evidence-guide__label">How to use it</span>
          <h3>Check before you act.</h3>
          <p>Choose what to check, send it to OMNI, then review the result.</p>
          <InternalLink className="button button--dark evidence-guide__cta" href="/api">Open the API <span>↗</span></InternalLink>
        </div>
        <ol className="evidence-guide__steps">
          <li><div className="evidence-guide__step-top"><span>01</span><strong>Choose</strong></div><p>Pick a package, repository, or endpoint.</p></li>
          <li><div className="evidence-guide__step-top"><span>02</span><strong>Check</strong></div><p>Send it to OMNI.</p></li>
          <li><div className="evidence-guide__step-top"><span>03</span><strong>Review</strong></div><p>Read the result before you install or pay.</p></li>
        </ol>
      </div>
    </div>
  );
}

function EcosystemMarquee() {
  const [activeLogo, setActiveLogo] = useState<string | null>(null);

  return (
    <div className="ecosystem-strip" aria-label="OMNI ecosystem">
      <div className="ecosystem-marquee">
        <div className="ecosystem-track">
          {[0, 1].map((groupIndex) => (
            <div className="ecosystem-group" aria-hidden={groupIndex === 1} key={groupIndex}>
              {ecosystemLogos.map((logo) => (
                <Magnetic key={`${groupIndex}-${logo.key}`} strength={0.1}>
                  <button
                    className={`ecosystem-item ${activeLogo === logo.key ? "is-active" : ""}`}
                    data-brand={logo.key}
                    type="button"
                    tabIndex={groupIndex === 1 ? -1 : 0}
                    aria-label={logo.label}
                    aria-pressed={activeLogo === logo.key}
                    onClick={() => setActiveLogo((current) => current === logo.key ? null : logo.key)}
                  >
                    <span className="ecosystem-logo" aria-hidden="true">
                      {logo.kind === "image" ? <img className="ecosystem-image-mark" src={logo.src} alt="" /> : <span className="ecosystem-mask-mark" style={{ "--brand-mask": `url(${logo.src})` } as CSSProperties} />}
                    </span>
                    <span className="ecosystem-label">{logo.label}</span>
                  </button>
                </Magnetic>
              ))}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Footer() {
  return (
    <footer className="site-footer">
      <div className="site-footer__body">
        <div className="site-footer__brand">
          <div className="site-footer__brand-head">
            <InternalLink className="site-footer__brand-link" href="/" aria-label="OMNI home">
              <span className="site-footer__brand-mark"><img src="/footer/omni-logo-bw.jpg" alt="" /></span>
              <span>OMNI</span>
            </InternalLink>
            <a className="site-footer__agent-badge" href="https://agents.circle.com/sell/score?url=api.askomni.xyz" target="_blank" rel="noopener noreferrer">
              <img src="https://agents.circle.com/sell/score/badge?url=api.askomni.xyz" alt="Accepts Agent Payments" />
            </a>
          </div>
          <p>Pre-execution trust &amp; risk for autonomous agents.</p>
          <p>OMNI returns deterministic, source-backed advice before execution.</p>
        </div>
        <div className="site-footer__details">
          <div className="site-footer__support">
            <span>Built with Circle x402</span>
            <span className="site-footer__support-marks" aria-label="Circle and Arc">
              <span><img className="site-footer__circle-mark" src="/footer/circle-logo.png" alt="" />Circle</span>
              <span><img className="site-footer__arc-mark" src="/footer/arc-logo.jpg" alt="" />Arc</span>
            </span>
          </div>
          <nav className="site-footer__social" aria-label="OMNI external links">
            <a href="https://github.com/riyannode/omni" target="_blank" rel="noopener noreferrer" aria-label="OMNI on GitHub">
              <span className="site-footer__icon site-footer__icon--light"><img src="/footer/github.svg" alt="" /></span>
              <span className="site-footer__icon site-footer__icon--dark"><img src="/footer/github-light.svg" alt="" /></span>
              <span>GitHub</span>
            </a>
            <a href="https://x.com/omnix402" target="_blank" rel="noopener noreferrer" aria-label="OMNI on X">
              <span className="site-footer__icon site-footer__icon--light"><img src="/footer/x.svg" alt="" /></span>
              <span className="site-footer__icon site-footer__icon--dark"><img src="/footer/x-light.svg" alt="" /></span>
              <span>X</span>
            </a>
            <a href="mailto:askomni.xyz@gmail.com" aria-label="Email OMNI">
              <span className="site-footer__mail-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M3.5 6.5h17v11h-17zM4 7l8 6 8-6" /></svg></span>
              <span>Email</span>
            </a>
          </nav>
        </div>
      </div>
      <div className="site-footer__bottom"><span>© 2026 OMNI</span><span>ADVISORY BY DESIGN</span></div>
    </footer>
  );
}

type BuilderCopyState = "idle" | "request" | "prompt" | "failed";

function ApiBuilder({ endpointId, values, onChange }: { endpointId: EndpointId; values: BuilderValues; onChange: (next: BuilderValues) => void }) {
  const resetRef = useRef<number | null>(null);
  const [copyState, setCopyState] = useState<BuilderCopyState>("idle");
  const input: InspectionInput = endpointId === "package"
    ? { endpointId, values: values.package }
    : endpointId === "repo"
      ? { endpointId, values: values.repo }
      : endpointId === "dependencies"
        ? { endpointId, values: values.dependencies }
        : { endpointId, values: values.preflight };
  const endpoint = API_ENDPOINTS.find((candidate) => candidate.id === endpointId);

  useEffect(() => () => {
    if (resetRef.current !== null) window.clearTimeout(resetRef.current);
  }, []);

  if (!endpoint) return null;
  const validationError = validateInspection(input);
  const request = validationError ? null : buildRequest(input);
  const updatePackage = (field: keyof PackageInput, value: string) => onChange({ ...values, package: { ...values.package, [field]: value } });
  const updateRepo = (field: keyof RepositoryInput, value: string) => onChange({ ...values, repo: { ...values.repo, [field]: value } });
  const updateDependency = (id: number, field: keyof PackageInput, value: string) => onChange({
    ...values,
    dependencies: values.dependencies.map((dependency) => dependency.id === id ? { ...dependency, [field]: value } : dependency),
  });
  const updatePreflight = (value: string) => onChange({ ...values, preflight: { url: value } });

  const copy = async (kind: "request" | "prompt") => {
    if (!request || validationError) return;
    try {
      await copyText(kind === "request" ? request.curl : buildAgentInspectionPrompt(input));
      setCopyState(kind);
    } catch {
      setCopyState("failed");
    }
    if (resetRef.current !== null) window.clearTimeout(resetRef.current);
    resetRef.current = window.setTimeout(() => setCopyState("idle"), 2600);
  };

  const requestLabel = copyState === "request" ? "COPIED" : copyState === "failed" ? "COPY FAILED — RETRY" : "COPY REQUEST";
  const promptLabel = copyState === "prompt" ? "PROMPT COPIED — PASTE TO YOUR AGENT" : copyState === "failed" ? "COPY FAILED — RETRY" : "COPY AGENT PROMPT";

  return (
    <div className="endpoint-builder" id={`${endpointId}-builder`}>
      <form className="builder-form" onSubmit={(event) => event.preventDefault()}>
        {endpointId === "package" && <fieldset>
          <legend>What package do you want to inspect?</legend>
          <div className="builder-fields builder-fields--three">
            <label><span>Ecosystem</span><input value={values.package.ecosystem} onChange={(event) => updatePackage("ecosystem", event.target.value)} placeholder="npm" maxLength={32} /></label>
            <label><span>Package</span><input value={values.package.name} onChange={(event) => updatePackage("name", event.target.value)} placeholder="express" maxLength={256} /></label>
            <label><span>Version</span><input value={values.package.version} onChange={(event) => updatePackage("version", event.target.value)} placeholder="5.2.1" maxLength={128} /></label>
          </div>
        </fieldset>}

        {endpointId === "repo" && <fieldset>
          <legend>What repository do you want to inspect?</legend>
          <div className="builder-fields builder-fields--two">
            <label><span>Owner</span><input value={values.repo.owner} onChange={(event) => updateRepo("owner", event.target.value)} placeholder="expressjs" maxLength={100} /></label>
            <label><span>Repository</span><input value={values.repo.repo} onChange={(event) => updateRepo("repo", event.target.value)} placeholder="express" maxLength={100} /></label>
          </div>
        </fieldset>}

        {endpointId === "dependencies" && <fieldset>
          <legend>What dependency set do you want to inspect?</legend>
          <div className="dependency-list">
            {values.dependencies.map((dependency, index) => <div className="dependency-row" key={dependency.id}>
              <span className="dependency-row__index">{String(index + 1).padStart(2, "0")}</span>
              <label><span>Ecosystem</span><input value={dependency.ecosystem} onChange={(event) => updateDependency(dependency.id, "ecosystem", event.target.value)} placeholder="npm" maxLength={32} /></label>
              <label><span>Package</span><input value={dependency.name} onChange={(event) => updateDependency(dependency.id, "name", event.target.value)} placeholder="express" maxLength={256} /></label>
              <label><span>Version</span><input value={dependency.version} onChange={(event) => updateDependency(dependency.id, "version", event.target.value)} placeholder="5.2.1" maxLength={128} /></label>
              <button className="builder-remove" type="button" onClick={() => onChange({ ...values, dependencies: values.dependencies.filter((candidate) => candidate.id !== dependency.id) })} disabled={values.dependencies.length === 1} aria-label={`Remove dependency ${index + 1}`}>Remove</button>
            </div>)}
          </div>
          <div className="dependency-controls"><button className="builder-add" type="button" onClick={() => onChange({ ...values, dependencies: [...values.dependencies, { id: Math.max(...values.dependencies.map((dependency) => dependency.id), 0) + 1, ecosystem: "", name: "", version: "" }] })} disabled={values.dependencies.length >= MAX_DEPENDENCIES}>+ Add dependency</button><span>{values.dependencies.length} / {MAX_DEPENDENCIES}</span></div>
        </fieldset>}

        {endpointId === "preflight" && <fieldset>
          <legend>What paid endpoint do you want OMNI to inspect?</legend>
          <label className="builder-field--full"><span>Target URL</span><input type="url" value={values.preflight.url} onChange={(event) => updatePreflight(event.target.value)} placeholder="https://example.com/api/resource" maxLength={2048} /></label>
        </fieldset>}
      </form>

      {validationError && <p className="builder-validation" role="status">{validationError}</p>}
      <div className="builder-preview">
        <div className="builder-preview__label"><span>Generated request</span><span>{request ? "ready to copy" : "waiting for required input"}</span></div>
        <pre>{request?.display ?? "Complete the fields above to generate the exact request."}</pre>
      </div>
      <div className="builder-actions">
        <button className="button button--dark" type="button" onClick={() => void copy("request")} disabled={!request} aria-label={`${requestLabel} for ${endpoint.path}`}>{requestLabel}</button>
        <button className="button button--text" type="button" onClick={() => void copy("prompt")} disabled={!request || Boolean(validationError)} aria-label={`${promptLabel} for ${endpoint.path}`}>{promptLabel}</button>
      </div>
      <p className="builder-copy-feedback" aria-live="polite">{copyState === "request" ? "COPIED" : copyState === "prompt" ? "PROMPT COPIED — PASTE TO YOUR AGENT" : copyState === "failed" ? "COPY FAILED — RETRY" : ""}</p>
    </div>
  );
}

function ApiPage({ search }: { search: string }) {
  const [theme, setTheme] = useState<Theme>(readThemePreference);
  const [selectedEndpoint, setSelectedEndpoint] = useState<EndpointId | null>(() => {
    const value = new URLSearchParams(search).get("endpoint");
    return isEndpointId(value) ? value : null;
  });
  const [builderValues, setBuilderValues] = useState<BuilderValues>(INITIAL_BUILDER_VALUES);
  const [copiedEndpoint, setCopiedEndpoint] = useState<string | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);
  const copyResetRef = useRef<number | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const endpointRowRefs = useRef(new Map<EndpointId, HTMLDivElement>());
  const pendingAnchorRef = useRef<{ endpointId: EndpointId; top: number } | null>(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    persistThemePreference(theme);
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "dark" ? "#0b0d10" : "#f2f3f1");
  }, [theme]);

  useEffect(() => () => {
    if (copyResetRef.current !== null) window.clearTimeout(copyResetRef.current);
  }, []);

  useEffect(() => {
    const value = new URLSearchParams(search).get("endpoint");
    setSelectedEndpoint(isEndpointId(value) ? value : null);
  }, [search]);

  useLayoutEffect(() => {
    const anchor = pendingAnchorRef.current;
    pendingAnchorRef.current = null;
    if (!anchor || selectedEndpoint !== anchor.endpointId) return;
    const row = endpointRowRefs.current.get(anchor.endpointId);
    if (!row) return;
    const delta = row.getBoundingClientRect().top - anchor.top;
    if (Math.abs(delta) > 0.5) window.scrollBy({ top: delta, left: 0, behavior: "auto" });
  }, [selectedEndpoint]);

  useGSAP(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    gsap.fromTo(".api-page__hero, .api-page__window, .api-page__endpoint", { y: 28, opacity: 0 }, { y: 0, opacity: 1, stagger: 0.08, duration: 0.8, ease: "power3.out" });
  }, { scope: rootRef });

  const toggleTheme = () => setTheme((current) => current === "light" ? "dark" : "light");
  const selectEndpoint = (endpointId: EndpointId) => {
    const clickedRow = endpointRowRefs.current.get(endpointId);
    if (clickedRow) pendingAnchorRef.current = { endpointId, top: clickedRow.getBoundingClientRect().top };
    const next = selectedEndpoint === endpointId ? "/api" : `/api?endpoint=${endpointId}`;
    setSelectedEndpoint(selectedEndpoint === endpointId ? null : endpointId);
    navigateInternal(next);
  };
  const copyEndpoint = async (endpoint: string) => {
    try {
      await copyText(endpoint);
      setCopiedEndpoint(endpoint);
      setCopyError(null);
    } catch {
      setCopiedEndpoint(null);
      setCopyError(endpoint);
    }
    if (copyResetRef.current !== null) window.clearTimeout(copyResetRef.current);
    copyResetRef.current = window.setTimeout(() => {
      setCopiedEndpoint(null);
      setCopyError(null);
    }, 1600);
  };

  return (
    <div ref={rootRef} className="site-shell api-page">
      <OrbitField className="orbit-field--page" />
      <header className="nav-shell">
        <InternalLink className="nav-logo" href="/" aria-label="OMNI home"><Logo /></InternalLink>
        <nav className="nav-links" aria-label="Primary navigation">
          <InternalLink href="/#top">Home</InternalLink>
          <InternalLink className="is-current" href="/api" aria-current="page">API</InternalLink>
          <InternalLink href="/docs">Docs</InternalLink>
        </nav>
        <div className="nav-actions"><ThemeToggle theme={theme} onChange={toggleTheme} /><Magnetic strength={0.18}><InternalLink className="nav-cta" href="/#top">Back to OMNI <span>↗</span></InternalLink></Magnetic></div>
      </header>

      <main className="page-shell" id="top">
        <section className="api-page__hero section-space" aria-labelledby="api-page-title">
          <p className="eyebrow">HTTP / OpenAPI</p>
          <h1 id="api-page-title">One API for runtime evidence.</h1>
          <p>Each route returns evidence you can inspect and use in your policy. Build the exact request, then hand a safe prompt to your agent.</p>
          <Magnetic><a className="button button--dark" href="https://api.askomni.xyz/openapi.yaml" target="_blank" rel="noreferrer">Read the contract <span>↗</span></a></Magnetic>
        </section>

        <section className="api-page__workspace section-space" aria-labelledby="api-workspace-title">
          <div className="api-page__window api-window">
            <div className="api-window__bar"><span /><span /><span /><strong>omni / preflight</strong></div>
            <ApiPreview />
          </div>
          <div className="api-page__endpoint-list endpoint-list" aria-labelledby="api-workspace-title">
            <div className="endpoint-list__head"><span id="api-workspace-title">Available endpoints</span><span>per request</span></div>
            {API_ENDPOINTS.map((endpoint) => {
              const routeLabel = `${endpoint.method} ${endpoint.path}`;
              const isSelected = selectedEndpoint === endpoint.id;
              return <Fragment key={endpoint.id}>
                <div ref={(node) => { if (node) endpointRowRefs.current.set(endpoint.id, node); else endpointRowRefs.current.delete(endpoint.id); }} className={`api-page__endpoint endpoint-list__row ${isSelected ? "is-active" : ""}`} data-method={endpoint.method.toLowerCase()}>
                  <div className="endpoint-list__main">
                    <div className="endpoint-route"><b>{endpoint.method}</b><code>{endpoint.path}</code><button className={`endpoint-copy${copiedEndpoint === routeLabel ? " is-copied" : ""}`} type="button" onClick={() => void copyEndpoint(routeLabel)} aria-label={`${copiedEndpoint === routeLabel ? "Copied" : copyError === routeLabel ? "Retry copy" : "Copy"} ${routeLabel}`} title={`${copiedEndpoint === routeLabel ? "Copied" : copyError === routeLabel ? "Retry copy" : "Copy endpoint"}`}><CopyIcon checked={copiedEndpoint === routeLabel} /></button></div>
                    <small>{endpoint.copy}</small>
                    <button className="endpoint-inspect" type="button" onClick={() => selectEndpoint(endpoint.id)} aria-expanded={isSelected} aria-controls={`${endpoint.id}-builder`}>{isSelected ? "Close builder ↖" : "Inspect ↗"}</button>
                  </div>
                  <strong>{endpoint.price}</strong>
                </div>
                {isSelected && <ApiBuilder endpointId={endpoint.id} values={builderValues} onChange={setBuilderValues} />}
              </Fragment>;
            })}
          </div>
        </section>

        <section className="api-page__notes section-space" aria-labelledby="api-notes-title">
          <div><p className="eyebrow">Integration notes</p><h2 id="api-notes-title">One contract for every runtime.</h2></div>
          <p>Hermes, Codex, Claude, OpenClaw, MCP clients, CI, and plain HTTP clients can read the same result and decide what to do next.</p>
        </section>
      </main>

      <Footer />
    </div>
  );
}

function highlightShellTokens(line: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const tokenPattern = /("(?:\\.|[^"])*"|'(?:\\.|[^'])*'|https?:\/\/[^\s'"\\]+|<[^>\n]+>|\$\{[^}\n]+\}|\$[A-Z_][A-Z0-9_]*|--?[A-Za-z][A-Za-z0-9-]*|#.*$|\b\d+(?:\.\d+)?\b)/g;
  let lastIndex = 0;
  let tokenIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = tokenPattern.exec(line)) !== null) {
    const start = match.index;
    const value = match[0];
    if (start > lastIndex) nodes.push(line.slice(lastIndex, start));
    const className = value.startsWith("#")
      ? "docs-token-comment"
      : value.startsWith("--") || (value.startsWith("-") && value.length > 1)
        ? "docs-token-flag"
        : value.startsWith("<")
          ? "docs-token-placeholder"
          : value.startsWith("$")
            ? "docs-token-variable"
            : value.startsWith('"') || value.startsWith("'") || value.startsWith("http")
              ? "docs-token-string"
              : "docs-token-number";
    nodes.push(<span className={className} key={`token-${tokenIndex}`}>{value}</span>);
    tokenIndex += 1;
    lastIndex = start + value.length;
  }
  if (lastIndex < line.length) nodes.push(line.slice(lastIndex));
  return nodes;
}

function highlightShell(code: string): ReactNode {
  return code.split("\n").map((line, lineIndex) => {
    const commandMatch = line.match(/^(\s*)(curl|circle|npm)(?=\s|$)/);
    const highlightedLine = commandMatch
      ? <>{commandMatch[1]}<span className="docs-token-command">{commandMatch[2]}</span>{highlightShellTokens(line.slice(commandMatch[0].length))}</>
      : highlightShellTokens(line);
    return <span className="docs-code-line" key={`line-${lineIndex}`}>{highlightedLine}</span>;
  });
}

function DocsCodeBlock({ label, code }: { label: string; code: string }) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "error">("idle");
  const copyCode = async () => {
    try {
      await copyText(code);
      setCopyState("copied");
    } catch {
      setCopyState("error");
    }
  };

  return <div className="docs-code-block">
    <div className="docs-code-block__bar"><span>{label}</span><button className={`docs-code-block__copy${copyState === "copied" ? " is-copied" : ""}`} type="button" onClick={() => void copyCode()} aria-label={`${copyState === "copied" ? "Copied" : copyState === "error" ? "Retry copy" : "Copy"} ${label} code`} title={`${copyState === "copied" ? "Copied" : copyState === "error" ? "Retry copy" : "Copy code"}`}><CopyIcon checked={copyState === "copied"} /></button></div>
    <pre><code>{highlightShell(code)}</code></pre>
  </div>;
}

function getEndpointDocsArticle(endpointId: EndpointId): DocsArticle {
  const endpoint = API_ENDPOINTS.find((candidate) => candidate.id === endpointId);
  if (!endpoint) throw new Error(`Missing documentation endpoint: ${endpointId}`);

  const details: Record<EndpointId, { title: string; intro: string; subject: string; result: string; decision: string }> = {
    package: {
      title: "Check a package before install.",
      intro: "Use package risk when an agent is about to install one exact package version. OMNI returns source-backed evidence for the caller to apply to its own policy.",
      subject: "Send the ecosystem, package name, and exact version. A versionless package name leaves too much room for the subject to change between the check and install.",
      result: "The assessment combines the risk score, advisory recommendation, coverage, evidence, source errors, and freshness information for that version.",
      decision: "Read the evidence before running the install. If coverage is low or a source failed, decide whether your policy stops, retries, or asks for review.",
    },
    repo: {
      title: "Check a repository before using it.",
      intro: "Use repository risk before an agent clones, reads, or depends on a GitHub repository. OMNI keeps the observed evidence separate from your runtime’s decision.",
      subject: "Send the GitHub owner and repository name. Check the repository you intend to use, not a lookalike or a fork chosen later in the flow.",
      result: "The response reports repository identity, activity, and named-source risk evidence alongside coverage and source errors.",
      decision: "Use the result before cloning or trusting repository instructions. The result is advisory; it never authorizes code execution by itself.",
    },
    dependencies: {
      title: "Check a dependency set in one request.",
      intro: "Use dependency risk when an agent has a package list and needs one assessment before it installs or updates the set.",
      subject: "Send the dependency coordinates as ecosystem, name, and exact version. Keep the list tied to the lockfile or planned install so the checked set is the executed set.",
      result: "OMNI returns one deterministic assessment for the submitted dependency set, including the evidence coverage and any source failures that affect it.",
      decision: "Review the resulting evidence before updating the environment. Treat a partial result as partial evidence, not an all-clear signal.",
    },
    preflight: {
      title: "Preflight an x402 endpoint before payment.",
      intro: "Use x402 preflight before an agent calls a paid endpoint. It records what OMNI can observe about the service and payment terms before the live request.",
      subject: "Send the exact endpoint URL. OMNI checks the service identity, its observed history, and the available x402 payment configuration for that resource.",
      result: "The response includes advisory evidence plus observed payment options. The execution-time HTTP 402 challenge remains the detail the caller must compare before paying.",
      decision: "Keep the preflight close to the paid call. Compare the live resource, USDC amount, network, and scheme against your own policy before the signed retry.",
    },
  };
  const detail = details[endpointId];
  const title = endpointId === "package" ? "Package risk" : endpointId === "repo" ? "Repository risk" : endpointId === "dependencies" ? "Dependency risk" : "x402 endpoint preflight";
  const requestExamples: Record<EndpointId, string> = {
    package: `curl -i --get 'https://api.askomni.xyz/v1/package/risk' \\
  --data-urlencode 'ecosystem=npm' \\
  --data-urlencode 'name=express' \\
  --data-urlencode 'version=5.2.1' \\
  -H 'Accept: application/json' \\
  -H 'Idempotency-Key: <UUID-v4>'`,
    repo: `curl -i --get 'https://api.askomni.xyz/v1/repo/risk' \\
  --data-urlencode 'owner=expressjs' \\
  --data-urlencode 'repo=express' \\
  -H 'Accept: application/json' \\
  -H 'Idempotency-Key: <UUID-v4>'`,
    dependencies: `curl -i -X POST 'https://api.askomni.xyz/v1/dependencies/risk' \\
  -H 'Accept: application/json' \\
  -H 'Content-Type: application/json' \\
  -H 'Idempotency-Key: <UUID-v4>' \\
  --data-raw '{
    "packages": [
      { "ecosystem": "npm", "name": "express", "version": "5.2.1" }
    ]
  }'`,
    preflight: `curl -i --get 'https://api.askomni.xyz/v1/x402/endpoint/preflight' \\
  --data-urlencode 'url=https://example.com/paid-resource' \\
  -H 'Accept: application/json' \\
  -H 'Idempotency-Key: <UUID-v4>'`,
  };

  return {
    label: "API reference",
    title: detail.title,
    intro: detail.intro,
    sections: [
      { id: "request", title: "Send the exact subject.", content: <><p><b>{endpoint.method}</b> <code>{endpoint.path}</code></p><p>{detail.subject}</p><div className="docs-reader__note"><strong>{endpoint.price} per request.</strong><p>Use a new UUID v4 idempotency key for this logical request. Keep the same key if you make its paid retry.</p></div></> },
      { id: "shell-example", title: "Run the request from a terminal.", content: <><p>This first request is unpaid. The protected route returns HTTP 402 until the caller sends a valid x402 payment. Keep the method, URL, headers, and body unchanged for the paid retry.</p><DocsCodeBlock label="shell" code={requestExamples[endpointId]} /></> },
      { id: "result", title: "Read what OMNI found.", content: <p>{detail.result}</p> },
      { id: "decision", title: "Keep the decision with your caller.", content: <p>{detail.decision}</p> },
    ],
  };
}

function getDocsArticle(articleId: DocsArticleId): DocsArticle {
  if (articleId === "package" || articleId === "repository" || articleId === "dependencies" || articleId === "preflight") return getEndpointDocsArticle(articleId === "repository" ? "repo" : articleId);

  const articles: Record<Exclude<DocsArticleId, "package" | "repository" | "dependencies" | "preflight">, DocsArticle> = {
    overview: {
      label: "OMNI Docs",
      title: "Check before an agent acts.",
      intro: "OMNI gives an agent source-backed risk evidence before it installs a package, uses a repository, checks dependencies, or pays an x402 endpoint.",
      actions: <><InternalLink className="button button--dark" href="/docs/quickstart">Start the quickstart <span>↗</span></InternalLink><a className="button button--text" href="https://api.askomni.xyz/llms.txt" target="_blank" rel="noreferrer">Read llms.txt <span>↗</span></a></>,
      sections: [
        { id: "what-omni-checks", title: "Choose the decision you need to make.", content: <div className="docs-resource-list"><InternalLink href="/docs/package-risk"><strong>Before an install</strong><span>Check one exact package version.</span><i>↗</i></InternalLink><InternalLink href="/docs/repository-risk"><strong>Before using a repository</strong><span>Check the repository behind the agent’s next step.</span><i>↗</i></InternalLink><InternalLink href="/docs/dependency-risk"><strong>Before an update</strong><span>Check the dependency set together.</span><i>↗</i></InternalLink><InternalLink href="/docs/x402-preflight"><strong>Before a paid call</strong><span>Check a service and its observed x402 terms.</span><i>↗</i></InternalLink></div> },
        { id: "advisory-boundary", title: "Evidence is not permission.", content: <div className="docs-reader__note"><strong>OMNI advises. Your policy decides.</strong><p>A result is a timestamped record from named sources. It does not approve a payment, execute code, or make a subject safe.</p></div> },
      ],
    },
    quickstart: {
      label: "Start here",
      title: "Make one check before you act.",
      intro: "The quickest way to use OMNI is to take the exact thing an agent is about to use, request the matching assessment, then read the evidence before the next action.",
      actions: <a className="button button--dark" href="https://api.askomni.xyz/openapi.yaml" target="_blank" rel="noreferrer">Open OpenAPI contract <span>↗</span></a>,
      sections: [
        { id: "choose", title: "1. Choose the exact subject.", content: <p>Use a package version, GitHub repository, dependency list, or x402 endpoint URL. The check is only as specific as the subject you send.</p> },
        { id: "request", title: "2. Send the matching request.", content: <p>Open the endpoint article in this Docs section. It shows the request shape, terminal command, and the fields you should read after payment succeeds.</p> },
        { id: "review", title: "3. Review evidence before the next action.", content: <p>Read the risk, recommendation, coverage, sources, errors, and freshness. Then let your caller policy choose whether to continue, stop, retry, or ask a person.</p> },
      ],
    },
    results: {
      label: "Understand a result",
      title: "Read the result, not just the score.",
      intro: "OMNI separates observed evidence from the caller’s decision. A low score does not make a subject safe, and missing evidence stays visible.",
      sections: [
        { id: "assessment-fields", title: "The assessment fields.", content: <dl className="docs-field-list"><div><dt><code>riskScore</code></dt><dd>0 to 100. Higher means more observed decision risk; source failures can increase it.</dd></div><div><dt><code>recommendation</code></dt><dd>Advisory next action from OMNI’s deterministic policy. Your caller policy remains in control.</dd></div><div><dt><code>evidenceCoverage</code></dt><dd>0 to 1. It shows how much subject-specific evidence was available, not the probability that a recommendation is correct.</dd></div><div><dt><code>freshness</code></dt><dd>When an expiry is present, obtain new evidence before you act after that time.</dd></div></dl> },
        { id: "caller-policy", title: "Let your policy make the call.", content: <p>Use the same fields consistently in your runtime. For example, require minimum evidence coverage for a paid action or stop whenever a source error blocks a critical check.</p> },
      ],
    },
    evidence: {
      label: "Understand a result",
      title: "Keep every fact traceable.",
      intro: "Evidence is a timestamped fact from a named source. OMNI keeps its source and any source failure visible so the caller can apply the right policy.",
      sections: [
        { id: "source-and-time", title: "Read the source and timestamp.", content: <p>Check where a fact came from and when OMNI observed it. Fresh evidence helps a caller see the current state; it does not predict every future change.</p> },
        { id: "source-errors", title: "Treat failures as part of the result.", content: <p>When a source cannot be read, OMNI shows the source error instead of pretending the check succeeded. Your policy can then stop, retry later, or continue with explicit limits.</p> },
        { id: "response-formats", title: "Use the format your client needs.", content: <div className="docs-reader__note"><strong>JSON is the default response.</strong><p>Successful requests also expose a deterministic Markdown artifact. Send <code>Accept: text/markdown</code> when you need only the human-readable version. Errors remain JSON.</p></div> },
      ],
    },
    payment: {
      label: "Payment and safety",
      title: "Check the live challenge before payment.",
      intro: "x402 preflight helps you inspect a service first. The live HTTP 402 challenge is still the payment request your caller must compare against policy before it signs or retries.",
      sections: [
        { id: "preflight", title: "1. Preflight the endpoint.", content: <p>Use <InternalLink href="/docs/x402-preflight">x402 preflight</InternalLink> to record the service identity and observed payment options before the paid call.</p> },
        { id: "challenge", title: "2. Read the exact 402 challenge.", content: <p>Ask the protected resource without paying. Compare the resource, USDC amount, network, and scheme in <code>PAYMENT-REQUIRED</code> with the preflight and your own policy.</p> },
        { id: "retry", title: "3. Retry once with a stable key.", content: <p>Reuse one UUID v4 <code>Idempotency-Key</code> for the same logical paid retry. If payment state is unclear, stop and reconcile instead of making a second charge.</p> },
      ],
    },
    security: {
      label: "Payment and safety",
      title: "Keep the trust boundary clear.",
      intro: "OMNI provides evidence before action. Your caller owns the authorization, the final policy, and the response to missing or stale evidence.",
      sections: [
        { id: "caller-controls", title: "The caller controls action.", content: <p>Do not treat an advisory recommendation as execution permission. The caller must decide whether it can install, clone, call, or pay after it reads the assessment.</p> },
        { id: "endpoint-safety", title: "Protect the request path.", content: <p>Only inspect valid public endpoints. Reject loopback, private-network, and otherwise unsafe probe targets before an outbound check can reach them.</p> },
        { id: "failure-mode", title: "Stop on an unclear paid state.", content: <p>Payment verification and settlement are separate from OMNI’s advisory result. If a paid retry has an unclear outcome, reconcile it rather than assuming success or attempting another charge.</p> },
      ],
    },
    architecture: {
      label: "Project reference",
      title: "See how the pieces fit together.",
      intro: "OMNI is designed to keep risk computation, payment handling, and caller-side enforcement separate so each part has a clear responsibility.",
      sections: [
        { id: "request-lifecycle", title: "A request has three stages.", content: <ol className="docs-steps docs-steps--compact"><li><span>1</span><div><strong>Inspect</strong><p>OMNI gathers deterministic evidence from named sources.</p></div></li><li><span>2</span><div><strong>Return</strong><p>The API returns an advisory assessment and traceable evidence.</p></div></li><li><span>3</span><div><strong>Enforce</strong><p>The caller applies its own policy before it takes an action.</p></div></li></ol> },
        { id: "further-reading", title: "Read the implementation details.", content: <div className="docs-resource-list"><a href="https://github.com/riyannode/omni/blob/main/docs/ARCHITECTURE.md" target="_blank" rel="noreferrer"><strong>Architecture</strong><span>Risk engine, durable paid requests, and caller-side enforcement.</span><i>↗</i></a><a href="https://github.com/riyannode/omni/tree/main/docs/adr" target="_blank" rel="noreferrer"><strong>Architecture decisions</strong><span>Runtime, Circle Gateway, and risk-model design choices.</span><i>↗</i></a></div> },
      ],
    },
    wallet: {
      label: "Project reference",
      title: "Set up a buyer wallet for OMNI.",
      intro: "This guide is for testing OMNI’s paid endpoints with Circle CLI. OMNI’s seller process belongs to the project and is not part of this setup.",
      sections: [
        { id: "wallet-boundary", title: "This wallet is only for buyer tests.", content: <><p>Circle CLI signs the payment from your Agent Wallet when you test an OMNI endpoint. The OMNI seller process is already part of the project. You do not configure, replace, or manage it from this guide.</p><div className="docs-reader__note"><strong>Only prepare the buyer wallet.</strong><p>The project handles the seller side. Your wallet is used to inspect, estimate, and authorize a test payment.</p></div></> },
        { id: "install-cli", title: "Install and check Circle CLI.", content: <><p>Install Circle CLI on the machine that will run the buyer test. Circle’s current CLI documentation requires Node.js v20.18.2 or later.</p><DocsCodeBlock label="shell" code={"npm install -g @circle-fin/cli@latest\ncircle --version"} /></> },
        { id: "login-testnet", title: "Log in to the testnet wallet.", content: <><p>Use a testnet session for OMNI buyer tests. Testnet and mainnet sessions are separate. An interactive login asks for the email and any verification input required by Circle.</p><DocsCodeBlock label="shell" code={"circle wallet login <email> --testnet\n\n# Inspect the wallet that login provisions\ncircle wallet list --chain ARC-TESTNET --type agent --output json"} /><p>For an agent that cannot answer an interactive prompt, use the two-step flow. Never put the email, OTP, or session data in the repository.</p><DocsCodeBlock label="shell" code={"circle wallet login <email> --testnet --init\ncircle wallet login --testnet --request <REQUEST_ID> --otp <OTP>"} /></> },
        { id: "fund-wallet", title: "Fund only the wallet you will test.", content: <><p>After checking the wallet address, fund that Agent Wallet on Arc Testnet. Do not search other chains for a replacement wallet when this guide is testing Arc.</p><DocsCodeBlock label="shell" code={"circle wallet fund --address <AGENT_WALLET> --chain ARC-TESTNET"} /></> },
        { id: "inspect-and-pay", title: "Inspect, estimate, then pay.", content: <><p>First inspect the exact OMNI URL. Then ask Circle CLI for an estimate. The estimate lets you check the chain and amount before a real payment is authorized.</p><DocsCodeBlock label="shell" code={"circle services inspect \\\n  \"https://api.askomni.xyz/v1/package/risk?ecosystem=npm&name=express&version=5.2.1\" --output json\n\ncircle services pay \\\n  \"https://api.askomni.xyz/v1/package/risk?ecosystem=npm&name=express&version=5.2.1\" \\\n  -X GET --address <AGENT_WALLET> --chain <CHAIN-FROM-INSPECT> \\\n  --max-amount 0.005 --estimate --output json"} /><p>Review the estimate. For a paid end-to-end test, run the same command again without <code>--estimate</code>. Keep the URL and request method unchanged.</p></> },
        { id: "wallet-safety", title: "Stop when the payment state is unclear.", content: <><p>Read the live HTTP 402 challenge before paying. Compare the resource, asset, amount, network, and scheme with your policy. Authorize at most one payment for the same request and stop if the result is uncertain.</p><p>Never commit OTPs, Circle session files, private keys, mnemonics, API keys, or wallet credentials. If Circle shows Terms of Use, read them yourself and decide whether to accept them. The agent must not accept terms on your behalf.</p></> },
      ],
    },
  };

  return articles[articleId];
}

function DocsPage({ pathname }: { pathname: string }) {
  const [theme, setTheme] = useState<Theme>(readThemePreference);
  const rootRef = useRef<HTMLDivElement>(null);
  const article = getDocsArticle(DOCS_ARTICLE_PATHS[pathname] ?? "overview");

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    persistThemePreference(theme);
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "dark" ? "#0b0d10" : "#f2f3f1");
  }, [theme]);

  useGSAP(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    gsap.fromTo(".docs-sidebar, .docs-reader, .docs-on-page", { y: 18, opacity: 0 }, { y: 0, opacity: 1, stagger: 0.08, duration: 0.6, ease: "power3.out" });
  }, { scope: rootRef });

  return (
    <div ref={rootRef} className="site-shell docs-page">
      <OrbitField className="orbit-field--page" />
      <header className="nav-shell">
        <InternalLink className="nav-logo" href="/" aria-label="OMNI home"><Logo /></InternalLink>
        <nav className="nav-links" aria-label="Primary navigation">
          <InternalLink href="/#top">Home</InternalLink>
          <InternalLink href="/api">API</InternalLink>
          <InternalLink className="is-current" href="/docs" aria-current="page">Docs</InternalLink>
        </nav>
        <div className="nav-actions"><ThemeToggle theme={theme} onChange={() => setTheme((current) => current === "light" ? "dark" : "light")} /><Magnetic strength={0.18}><a className="nav-cta" href="https://github.com/riyannode/omni" target="_blank" rel="noreferrer">Source repository <span>↗</span></a></Magnetic></div>
      </header>

      <main className="page-shell docs-layout-page" id="top">
        <div className="docs-layout">
          <aside className="docs-sidebar" aria-label="Documentation navigation">
            <InternalLink className="docs-sidebar__home" href="/docs"><span>OMNI</span><strong>Documentation</strong></InternalLink>
            <nav className="docs-sidebar__nav" aria-label="Documentation sections">
              {DOCS_NAV_GROUPS.map((group) => (
                <section className="docs-sidebar__group" key={group.label}>
                  <h2>{group.label}</h2>
                  {group.items.map((item) => <InternalLink key={`${group.label}-${item.label}`} href={item.href} aria-current={item.href === pathname ? "page" : undefined}>{item.label}</InternalLink>)}
                </section>
              ))}
            </nav>
            <a className="docs-sidebar__github" href="https://github.com/riyannode/omni" target="_blank" rel="noreferrer">Browse OMNI on GitHub <span>↗</span></a>
          </aside>

          <article className="docs-reader" aria-labelledby="docs-page-title">
            <header className="docs-reader__intro">
              <p className="docs-reader__label">{article.label}</p>
              <h1 id="docs-page-title">{article.title}</h1>
              <p>{article.intro}</p>
              {article.actions ? <div className="docs-reader__actions">{article.actions}</div> : null}
            </header>

            {article.sections.map((section, index) => <section className={`docs-reader__section${index === article.sections.length - 1 ? " docs-reader__section--last" : ""}`} id={section.id} aria-labelledby={`${section.id}-title`} key={section.id}><h2 id={`${section.id}-title`}>{section.title}</h2>{section.content}</section>)}
          </article>

          <aside className="docs-on-page" aria-label="On this page">
            <p>On this page</p>{article.sections.map((section) => <a href={`#${section.id}`} key={section.id}>{section.title.replace(/^\d\. /, "")}</a>)}
          </aside>
        </div>
      </main>

      <Footer />
    </div>
  );
}

function LandingPage() {
  const [theme, setTheme] = useState<Theme>(readThemePreference);
  const rootRef = useRef<HTMLDivElement>(null);
  const restoreFrameRef = useRef<number | null>(null);
  const restoreTimerRef = useRef<number | null>(null);

  useEffect(() => () => {
    if (restoreFrameRef.current !== null) window.cancelAnimationFrame(restoreFrameRef.current);
    if (restoreTimerRef.current !== null) window.clearTimeout(restoreTimerRef.current);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    persistThemePreference(theme);
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "dark" ? "#0b0d10" : "#f2f3f1");
  }, [theme]);

  useGSAP(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const intro = gsap.timeline({ defaults: { ease: "power3.out" } });
    intro.fromTo(".nav-shell", { y: -24, opacity: 0 }, { y: 0, opacity: 1, duration: 0.8 })
      .fromTo(".hero-kicker, .hero-title, .hero-copy, .hero-actions", { y: 26, opacity: 0 }, { y: 0, opacity: 1, duration: 0.85, stagger: 0.08 }, "-=0.45")
      .fromTo(".interceptor-card", { y: 44, opacity: 0, rotate: 2 }, { y: 0, opacity: 1, rotate: 0, duration: 1.1 }, "-=0.7");

    gsap.to(".hero-copy", { yPercent: -6, ease: "none", scrollTrigger: { trigger: ".hero", start: "top top", end: "bottom top", scrub: true } });
    gsap.to(".hero-visual", { yPercent: 13, rotate: -2, ease: "none", scrollTrigger: { trigger: ".hero", start: "top top", end: "bottom top", scrub: true } });
    gsap.to(".scrub-word", { opacity: 1, stagger: 0.06, ease: "none", scrollTrigger: { trigger: ".thesis-section", start: "top 70%", end: "bottom 65%", scrub: true } });
  }, { scope: rootRef });

  const toggleTheme = () => {
    const scrollTop = window.scrollY;
    setTheme((current) => current === "light" ? "dark" : "light");
    const restoreScroll = () => window.scrollTo({ top: scrollTop, left: 0, behavior: "auto" });
    if (restoreFrameRef.current !== null) window.cancelAnimationFrame(restoreFrameRef.current);
    if (restoreTimerRef.current !== null) window.clearTimeout(restoreTimerRef.current);
    restoreFrameRef.current = window.requestAnimationFrame(() => {
      restoreScroll();
      restoreFrameRef.current = null;
    });
    restoreTimerRef.current = window.setTimeout(() => {
      restoreScroll();
      restoreTimerRef.current = null;
    }, 180);
  };

  return (
    <div ref={rootRef} className="site-shell">
      <OrbitField className="orbit-field--page" />
      <header className="nav-shell">
        <InternalLink className="nav-logo" href="#top" aria-label="OMNI home"><Logo /></InternalLink>
        <nav className="nav-links" aria-label="Primary navigation">
          <InternalLink href="/#top">Home</InternalLink>
          <InternalLink href="/api">API</InternalLink>
          <InternalLink href="/docs">Docs</InternalLink>
        </nav>
        <div className="nav-actions"><ThemeToggle theme={theme} onChange={toggleTheme} /><Magnetic strength={0.18}><InternalLink className="nav-cta" href="/api">Integrate OMNI <span>↗</span></InternalLink></Magnetic></div>
      </header>

      <main className="page-shell" id="top">
        <section className="hero" aria-labelledby="hero-title">
          <div className="hero-grid">
            <div className="hero-copy">
              <p className="hero-kicker"><span className="kicker-line" /> checks before execution</p>
              <h1 id="hero-title" className="hero-title">Check risk before agents act.</h1>
              <p className="hero-lede">Before an agent installs software, calls a service, or pays, OMNI checks the software, service, and payment details.</p>
              <div className="hero-actions"><Magnetic><AgentQuickTestButton /></Magnetic><Magnetic strength={0.18}><InternalLink className="button button--text" href="/api">Open the API <span>↗</span></InternalLink></Magnetic></div>
              <InternalLink className="hero-secondary-link" href="#supply-chain-evidence">See how it works <span>↘</span></InternalLink>
            </div>
            <div className="hero-visual"><InterceptorCard /></div>
          </div>
        </section>

        <section className="thesis-section section-space" id="thesis" aria-labelledby="thesis-title">
          <div className="section-intro"><h2 id="thesis-title">Agents move fast. <span className="scrub-word">Evidence</span> makes the next step clear.</h2></div>
          <p className="thesis-copy"><span className="scrub-word">A marketplace listing shows what is listed, but it does not approve the service.</span> <span className="scrub-word">An HTTP 402 challenge shows what a service asks for, not whether it should be trusted.</span> <span className="scrub-word">OMNI shows both details before the next action.</span></p>
        </section>

        <section className="evidence-section section-space" id="evidence" aria-labelledby="evidence-title">
          <div className="evidence-intro"><h2 id="evidence-title">One action. Three checks.</h2><p>Before an agent installs or pays, OMNI checks the request. A failed source stays visible in the result.</p></div>
          <EvidenceShowcase />
        </section>

        <EcosystemMarquee />

        <section className="final-section section-space" aria-labelledby="final-title"><div className="final-copy"><h2 id="final-title">Put evidence before action.</h2><p>Give your runtime a policy check it can explain.</p><div className="hero-actions"><Magnetic><InternalLink className="button button--dark" href="/api">Integrate OMNI <span>↗</span></InternalLink></Magnetic><Magnetic strength={0.18}><a className="button button--text" href="https://github.com/riyannode/omni" target="_blank" rel="noreferrer">View the repository <span>↗</span></a></Magnetic></div></div></section>
      </main>

      <Footer />
    </div>
  );
}

function App() {
  const [routeLocation, setRouteLocation] = useState<RouteLocation>(readRouteLocation);
  const routeLocationRef = useRef(routeLocation);

  useEffect(() => {
    const onPopState = () => {
      const nextLocation = readRouteLocation();
      const previousLocation = routeLocationRef.current;
      routeLocationRef.current = nextLocation;
      const shouldTransition = nextLocation.pathname !== previousLocation.pathname || nextLocation.hash !== previousLocation.hash;
      updateRouteLocation(setRouteLocation, shouldTransition);
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  useEffect(() => {
    const targetId = routeLocation.hash.slice(1);
    const frame = window.requestAnimationFrame(() => scrollToRouteTarget(targetId));
    const settleTimer = window.setTimeout(() => scrollToRouteTarget(targetId), 80);
    return () => {
      window.cancelAnimationFrame(frame);
      window.clearTimeout(settleTimer);
    };
  }, [routeLocation.pathname, routeLocation.hash]);

  useEffect(() => {
    if (routeLocation.pathname !== "/docs") return;
    const legacyPath = DOCS_LEGACY_HASH_PATHS[routeLocation.hash.slice(1)];
    if (legacyPath) navigateInternal(legacyPath);
  }, [routeLocation.hash, routeLocation.pathname]);

  return routeLocation.pathname.startsWith("/docs") ? <DocsPage pathname={routeLocation.pathname} /> : routeLocation.pathname === "/api" ? <ApiPage search={routeLocation.search} /> : <LandingPage />;
}

export default App;
