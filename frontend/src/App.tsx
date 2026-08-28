import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { type AnchorHTMLAttributes, type CSSProperties, type MouseEvent, type ReactNode, useEffect, useRef, useState } from "react";
import { copyAgentQuickTestPrompt } from "./agent-quick-test";

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

function updateRouteLocation(setLocation: (location: RouteLocation) => void): void {
  const commit = () => setLocation(readRouteLocation());
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const transitionDocument = document as unknown as ViewTransitionDocument;
  if (typeof transitionDocument.startViewTransition === "function" && !reduceMotion) transitionDocument.startViewTransition(commit);
  else commit();
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

const evidencePlanes = [
  {
    key: "supply-chain",
    index: "01",
    title: "Supply-chain evidence",
    sources: "OSV · CISA KEV · npm · OpenSSF",
    copy: "OMNI checks a package or repository before an agent installs the package or uses the repository.",
    route: "GET /v1/package/risk",
  },
  {
    key: "identity",
    index: "02",
    title: "Service identity",
    sources: "Circle Discovery · x402 probe",
    copy: "OMNI checks who provides the endpoint, its history, and the limits of its x402 handshake.",
    route: "GET /v1/x402/endpoint/preflight",
  },
  {
    key: "payment",
    index: "03",
    title: "Payment configuration",
    sources: "payTo · network · price · history",
    copy: "OMNI captures payment terms during preflight so callers can compare them against the actual challenge before payment.",
    route: "preflightContext.paymentOptions",
  },
];

const ecosystemLogos = [
  { key: "circle", label: "CIRCLE", src: "/circle-gradient.png", kind: "image" as const },
  { key: "arc", label: "ARC", src: "/arc-clean.png", kind: "mask" as const },
  { key: "mcp", label: "MCP", src: "/mcp-mask.png", kind: "mask" as const },
  { key: "x402", label: "X402", src: "/x402-clean.png", kind: "mask" as const },
];

const apiEndpoints = [
  { method: "GET", path: "/v1/package/risk", price: "$0.005 USDC", copy: "Check package origin, advisories, and release signals before install." },
  { method: "GET", path: "/v1/repo/risk", price: "$0.01 USDC", copy: "Check repository identity, activity, and risk evidence from named sources." },
  { method: "POST", path: "/v1/dependencies/risk", price: "$0.05 USDC", copy: "Check a dependency set in one request." },
  { method: "GET", path: "/v1/x402/endpoint/preflight", price: "$0.01 USDC", copy: "Check service identity and payment details before a paid call." },
];

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

function EvidenceBento() {
  const [activePlane, setActivePlane] = useState(0);
  const active = evidencePlanes[activePlane];
  useEffect(() => {
    const interval = window.setInterval(() => setActivePlane((current) => (current + 1) % evidencePlanes.length), 4300);
    return () => window.clearInterval(interval);
  }, []);

  return (
    <div className="evidence-grid">
      <article className="evidence-card evidence-card--supply reveal-card">
        <div className="card-header"><span>Supply chain</span><span className="card-index">{evidencePlanes[0].index}</span></div>
        <div className="evidence-card__visual supply-visual"><div className="supply-node supply-node--a" /><div className="supply-node supply-node--b" /><div className="supply-node supply-node--c" /><span className="supply-line" /></div>
        <h3>See what the agent will install.</h3>
        <p>{evidencePlanes[0].copy}</p>
        <span className="route-code">{evidencePlanes[0].route}</span>
      </article>
      <article className="evidence-card evidence-card--identity reveal-card">
        <div className="card-header"><span>Service identity</span><span className="card-index">{evidencePlanes[1].index}</span></div>
        <div className="identity-visual"><span className="identity-crosshair" /><span className="identity-ring" /><span className="identity-label">CIRCLE / DISCOVERY</span></div>
        <h3>See the service clearly.</h3>
        <p>{evidencePlanes[1].copy}</p>
        <span className="route-code">{evidencePlanes[1].route}</span>
      </article>
      <article className="evidence-card evidence-card--payment reveal-card">
        <div className="card-header"><span>Payment config</span><span className="card-index">{evidencePlanes[2].index}</span></div>
        <div className="payment-visual"><span className="payment-pill">payTo</span><span className="payment-pill">network</span><span className="payment-pill">atomic price</span><span className="payment-arrow">↗</span></div>
        <h3>Check payment before the wallet pays.</h3>
        <p>{evidencePlanes[2].copy}</p>
        <span className="route-code">{evidencePlanes[2].route}</span>
      </article>
      <article className="evidence-card evidence-card--coverage reveal-card">
        <div className="card-header"><span>Assessment contract</span><span className="status-chip"><i /> deterministic</span></div>
        <div className="coverage-row"><span>riskScore</span><span>0 to 100</span></div>
        <div className="coverage-row"><span>recommendation</span><span>advisory</span></div>
        <div className="coverage-row"><span>evidenceCoverage</span><span>0 to 1</span></div>
        <div className="coverage-row"><span>sourceErrors</span><span>explicit</span></div>
        <p>Evidence is a timestamped fact from a named source. It is not a verdict, probability, or payment approval.</p>
      </article>
      <div className="evidence-rail" aria-label="Evidence plane selector">
        <div className="evidence-rail__buttons">
          {evidencePlanes.map((plane, index) => (
            <Magnetic key={plane.key} strength={0.14}>
              <button className={index === activePlane ? "is-active" : ""} type="button" onClick={() => setActivePlane(index)} onFocus={() => setActivePlane(index)} aria-pressed={index === activePlane}>
                <span>{plane.index}</span>{plane.title}
              </button>
            </Magnetic>
          ))}
        </div>
        <p className="evidence-rail__copy">{active.sources}</p>
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

function ApiPage() {
  const [theme, setTheme] = useState<Theme>(readThemePreference);
  const [copiedEndpoint, setCopiedEndpoint] = useState<string | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);
  const copyResetRef = useRef<number | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    persistThemePreference(theme);
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "dark" ? "#0b0d10" : "#f2f3f1");
  }, [theme]);

  useEffect(() => () => {
    if (copyResetRef.current !== null) window.clearTimeout(copyResetRef.current);
  }, []);

  useGSAP(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    gsap.fromTo(".api-page__hero, .api-page__window, .api-page__endpoint", { y: 28, opacity: 0 }, { y: 0, opacity: 1, stagger: 0.08, duration: 0.8, ease: "power3.out" });
  }, { scope: rootRef });

  const toggleTheme = () => setTheme((current) => current === "light" ? "dark" : "light");
  const copyEndpoint = async (endpoint: string) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(endpoint);
      } else {
        const textarea = document.createElement("textarea");
        textarea.value = endpoint;
        textarea.setAttribute("readonly", "true");
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        const copied = document.execCommand("copy");
        textarea.remove();
        if (!copied) throw new Error("Clipboard unavailable");
      }
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
          <InternalLink href="/#thesis">Thesis</InternalLink>
          <InternalLink href="/#evidence">Evidence</InternalLink>
          <InternalLink className="is-current" href="/api" aria-current="page">API</InternalLink>
        </nav>
        <div className="nav-actions"><ThemeToggle theme={theme} onChange={toggleTheme} /><Magnetic strength={0.18}><InternalLink className="nav-cta" href="/#top">Back to OMNI <span>↗</span></InternalLink></Magnetic></div>
      </header>

      <main className="page-shell" id="top">
        <section className="api-page__hero section-space" aria-labelledby="api-page-title">
          <p className="eyebrow">HTTP / OpenAPI</p>
          <h1 id="api-page-title">One API for runtime evidence.</h1>
          <p>Each route returns evidence you can inspect and use in your policy. OMNI does not approve actions or settle payments.</p>
          <Magnetic><a className="button button--dark" href="https://github.com/riyannode/omni/blob/main/openapi.yaml" target="_blank" rel="noreferrer">Read the contract <span>↗</span></a></Magnetic>
        </section>

        <section className="api-page__workspace section-space" aria-labelledby="api-workspace-title">
          <div className="api-page__window api-window">
            <div className="api-window__bar"><span /><span /><span /><strong>omni / preflight</strong></div>
            <div className="api-window__body">
              <p><span className="syntax-muted">GET</span> /v1/x402/endpoint/preflight</p>
              <p className="syntax-muted">Accept: application/json</p>
              <p className="syntax-muted">Idempotency-Key: UUID v4</p>
              <div className="api-divider" />
              <p><span className="syntax-key">recommendation</span>: <span className="syntax-value">advisory</span></p>
              <p><span className="syntax-key">evidenceCoverage</span>: <span className="syntax-value">source-derived</span></p>
              <p><span className="syntax-key">policyVersion</span>: <span className="syntax-value">deterministic</span></p>
              <div className="api-cursor" />
            </div>
          </div>
          <div className="api-page__endpoint-list endpoint-list" aria-labelledby="api-workspace-title">
            <div className="endpoint-list__head"><span id="api-workspace-title">Available endpoints</span><span>per request</span></div>
            {apiEndpoints.map((endpoint) => (
              <div className="api-page__endpoint endpoint-list__row" data-method={endpoint.method.toLowerCase()} key={endpoint.path}>
                <span>
                  <span className="endpoint-route"><b>{endpoint.method}</b><code>{endpoint.path}</code><button className={`endpoint-copy${copiedEndpoint === `${endpoint.method} ${endpoint.path}` ? " is-copied" : ""}`} type="button" onClick={() => void copyEndpoint(`${endpoint.method} ${endpoint.path}`)} aria-label={`${copiedEndpoint === `${endpoint.method} ${endpoint.path}` ? "Copied" : copyError === `${endpoint.method} ${endpoint.path}` ? "Retry copy" : "Copy"} ${endpoint.method} ${endpoint.path}`} title={`${copiedEndpoint === `${endpoint.method} ${endpoint.path}` ? "Copied" : copyError === `${endpoint.method} ${endpoint.path}` ? "Retry copy" : "Copy endpoint"}`}><CopyIcon checked={copiedEndpoint === `${endpoint.method} ${endpoint.path}`} /></button></span>
                  <small>{endpoint.copy}</small>
                </span>
                <strong>{endpoint.price}</strong>
              </div>
            ))}
          </div>
        </section>

        <section className="api-page__notes section-space" aria-labelledby="api-notes-title">
          <div><p className="eyebrow">Integration notes</p><h2 id="api-notes-title">One contract for every runtime.</h2></div>
          <p>Hermes, Codex, Claude, OpenClaw, MCP clients, CI, and plain HTTP clients can read the same result and decide what to do next.</p>
        </section>
      </main>

      <footer className="site-footer"><div className="footer-links"><InternalLink href="/">OMNI</InternalLink><InternalLink href="/#thesis">Thesis</InternalLink><InternalLink href="/#evidence">Evidence</InternalLink><InternalLink href="/api" aria-current="page">API</InternalLink><a href="https://github.com/riyannode/omni" target="_blank" rel="noreferrer">GitHub ↗</a></div><span>OMNI / advisory by design</span></footer>
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
    gsap.fromTo(".reveal-card", { y: 52, opacity: 0, scale: 0.96 }, { y: 0, opacity: 1, scale: 1, stagger: 0.12, ease: "power3.out", scrollTrigger: { trigger: ".evidence-section", start: "top 70%", end: "top 25%", scrub: 1 } });

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
          <InternalLink href="#thesis">Thesis</InternalLink>
          <InternalLink href="#evidence">Evidence</InternalLink>
          <InternalLink href="/api">API</InternalLink>
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
              <InternalLink className="hero-secondary-link" href="#evidence">See how it works <span>↘</span></InternalLink>
              <p className="hero-quick-test-note">NO SIGNUP · NO API KEY · TESTNET · QUICK TEST $0.005</p>
              <p className="hero-note">OMNI shows the evidence. Your policy decides what to allow.</p>
            </div>
            <div className="hero-visual"><InterceptorCard /></div>
          </div>
        </section>

        <section className="thesis-section section-space" id="thesis" aria-labelledby="thesis-title">
          <div className="section-intro"><h2 id="thesis-title">Agents move fast. <span className="scrub-word">Evidence</span> makes the next step clear.</h2></div>
          <p className="thesis-copy"><span className="scrub-word">A marketplace listing shows what is listed, but it does not approve the service.</span> <span className="scrub-word">An HTTP 402 challenge shows what a service asks for, not whether it should be trusted.</span> <span className="scrub-word">OMNI shows both details before the next action.</span></p>
        </section>

        <section className="evidence-section section-space" id="evidence" aria-labelledby="evidence-title">
          <div className="section-heading"><div><h2 id="evidence-title">One action. Three checks.</h2></div><p>These checks produce one deterministic result. If a data source fails, the result says so.</p></div>
          <EvidenceBento />
        </section>

        <EcosystemMarquee />

        <section className="final-section section-space" aria-labelledby="final-title"><div className="final-copy"><h2 id="final-title">Put evidence before action.</h2><p>Give your runtime a policy check it can explain.</p><div className="hero-actions"><Magnetic><InternalLink className="button button--dark" href="/api">Integrate OMNI <span>↗</span></InternalLink></Magnetic><Magnetic strength={0.18}><a className="button button--text" href="https://github.com/riyannode/omni" target="_blank" rel="noreferrer">View the repository <span>↗</span></a></Magnetic></div></div></section>
      </main>

      <footer className="site-footer"><div className="footer-links"><InternalLink href="#thesis">Thesis</InternalLink><InternalLink href="#evidence">Evidence</InternalLink><InternalLink href="/api">API</InternalLink><a href="https://github.com/riyannode/omni" target="_blank" rel="noreferrer">GitHub ↗</a></div><span>OMNI / advisory by design</span></footer>
    </div>
  );
}

function App() {
  const [routeLocation, setRouteLocation] = useState<RouteLocation>(readRouteLocation);

  useEffect(() => {
    const onPopState = () => updateRouteLocation(setRouteLocation);
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      const targetId = routeLocation.hash.slice(1);
      const target = targetId ? document.getElementById(targetId) : null;
      if (target) target.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
      else window.scrollTo({ top: 0, left: 0, behavior: "auto" });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [routeLocation.pathname, routeLocation.search, routeLocation.hash]);

  return routeLocation.pathname === "/api" ? <ApiPage /> : <LandingPage />;
}

export default App;
