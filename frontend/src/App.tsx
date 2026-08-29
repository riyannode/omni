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
  let top = 0;
  let current = target;
  while (current) {
    top += current.offsetTop;
    current = current.offsetParent as HTMLElement | null;
  }
  top = target ? Math.max(0, top - 96) : 0;
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

const INITIAL_BUILDER_VALUES: BuilderValues = {
  package: { ecosystem: "npm", name: "express", version: "5.2.1" },
  repo: { owner: "expressjs", repo: "express" },
  dependencies: [{ id: 1, ecosystem: "npm", name: "express", version: "5.2.1" }],
  preflight: { url: "" },
};

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
      <article id="supply-chain-evidence" className="evidence-card evidence-card--supply reveal-card">
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
          <p>Source-attributed, deterministic, and advisory by design.</p>
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
          <InternalLink href="/#thesis">Thesis</InternalLink>
          <InternalLink href="/#evidence">Evidence</InternalLink>
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

function DocsPage() {
  const [theme, setTheme] = useState<Theme>(readThemePreference);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    persistThemePreference(theme);
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "dark" ? "#0b0d10" : "#f2f3f1");
  }, [theme]);

  useGSAP(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    gsap.fromTo(".docs-page__hero, .docs-card", { y: 24, opacity: 0 }, { y: 0, opacity: 1, stagger: 0.06, duration: 0.75, ease: "power3.out" });
  }, { scope: rootRef });

  return (
    <div ref={rootRef} className="site-shell docs-page">
      <OrbitField className="orbit-field--page" />
      <header className="nav-shell">
        <InternalLink className="nav-logo" href="/" aria-label="OMNI home"><Logo /></InternalLink>
        <nav className="nav-links" aria-label="Primary navigation">
          <InternalLink href="/#thesis">Thesis</InternalLink>
          <InternalLink href="/#evidence">Evidence</InternalLink>
          <InternalLink href="/api">API</InternalLink>
          <InternalLink className="is-current" href="/docs" aria-current="page">Docs</InternalLink>
        </nav>
        <div className="nav-actions"><ThemeToggle theme={theme} onChange={() => setTheme((current) => current === "light" ? "dark" : "light")} /><Magnetic strength={0.18}><InternalLink className="nav-cta" href="/#top">Back to OMNI <span>↗</span></InternalLink></Magnetic></div>
      </header>

      <main className="page-shell" id="top">
        <section className="docs-page__hero section-space" aria-labelledby="docs-page-title">
          <p className="eyebrow">OMNI / Docs</p>
          <h1 id="docs-page-title">Evidence before the next action.</h1>
          <p>Use OMNI as a deterministic, source-attributed trust and risk layer before an agent installs software, trusts a repository, evaluates dependencies, or pays an x402 endpoint.</p>
          <div className="hero-actions"><Magnetic><InternalLink className="button button--dark" href="/#top">Try with your agent <span>↗</span></InternalLink></Magnetic><Magnetic strength={0.18}><a className="button button--text" href="https://api.askomni.xyz/llms.txt" target="_blank" rel="noreferrer">Read llms.txt <span>↗</span></a></Magnetic></div>
        </section>

        <section className="docs-section section-space" aria-labelledby="docs-getting-started">
          <div className="section-heading"><div><p className="eyebrow">Getting started</p><h2 id="docs-getting-started">A small contract with a clear handoff.</h2></div><p>OMNI returns evidence and advisory output. Caller policy and wallet enforcement decide what happens next.</p></div>
          <div className="docs-card docs-card--wide"><strong>GETTING STARTED</strong><p>Read the machine-readable <a href="https://api.askomni.xyz/llms.txt" target="_blank" rel="noreferrer">llms.txt</a>, choose an endpoint, and use the API builder to generate an exact request plus a safe agent prompt.</p><InternalLink className="docs-action" href="/api">Open the API builder <span>↗</span></InternalLink></div>
        </section>

        <section className="docs-section section-space" aria-labelledby="docs-api-reference">
          <div className="section-heading"><div><p className="eyebrow">API reference</p><h2 id="docs-api-reference">Four inspection routes.</h2></div><p>Prices and inputs mirror the checked-in OpenAPI contract. The builder stays responsible for request construction only.</p></div>
          <div className="docs-reference-grid">{API_ENDPOINTS.map((endpoint) => <article className="docs-card" key={endpoint.id}><div className="docs-card__route"><b>{endpoint.method}</b><code>{endpoint.path}</code></div><h3>{endpoint.id === "package" ? "Package Risk" : endpoint.id === "repo" ? "Repository Risk" : endpoint.id === "dependencies" ? "Dependency Risk" : "x402 Endpoint Preflight"}</h3><p>{endpoint.copy}</p><span className="docs-card__price">{endpoint.price} · {endpoint.atomicAmount} atomic</span><InternalLink className="docs-action" href={`/api?endpoint=${endpoint.id}`}>Open in API builder <span>↗</span></InternalLink></article>)}</div>
          <a className="docs-contract-link" href="https://api.askomni.xyz/openapi.yaml" target="_blank" rel="noreferrer">Open the canonical OpenAPI specification <span>↗</span></a>
        </section>

        <section className="docs-section section-space" aria-labelledby="docs-payments">
          <div className="section-heading"><div><p className="eyebrow">Payments</p><h2 id="docs-payments">Challenge first. Pay once.</h2></div><p>x402 negotiation keeps the live payment requirements authoritative at execution time.</p></div>
          <div className="docs-detail-grid"><article className="docs-card"><strong>HTTP 402 NEGOTIATION</strong><p>Request the exact OMNI resource without payment first. Inspect the `PAYMENT-REQUIRED` challenge, then submit a `PAYMENT-SIGNATURE` only when the resource, USDC asset, amount, network, and scheme satisfy caller policy.</p></article><article className="docs-card"><strong>REPLAY + IDEMPOTENCY</strong><p>Use one UUID v4 `Idempotency-Key` for one logical request and reuse it unchanged for the paid retry. A completed result can replay without another payment.</p></article><article className="docs-card"><strong>SETTLEMENT STATE</strong><p>`PAYMENT-RESPONSE` carries the settlement receipt when available. If payment state is uncertain, stop and do not retry automatically.</p></article></div>
        </section>

        <section className="docs-section section-space" aria-labelledby="docs-responses">
          <div className="section-heading"><div><p className="eyebrow">Responses</p><h2 id="docs-responses">Structured evidence, readable twice.</h2></div><p>JSON is canonical for machines; the deterministic Markdown artifact is ready for people and reports.</p></div>
          <div className="docs-detail-grid"><article className="docs-card"><strong>JSON ASSESSMENT</strong><p>Successful JSON responses include the assessment fields, source-attributed evidence, source errors, freshness, and an additive artifact object.</p></article><article className="docs-card"><strong>MARKDOWN ARTIFACT</strong><p>`artifact.content` is a deterministic Markdown representation of the same result. Its fixed filename and `text/markdown` media type are returned by OMNI.</p></article><article className="docs-card"><strong>COMMON HTTP ERRORS</strong><p>`400` means invalid input, `402` means payment is required, `406` means the representation is unsupported, `409` means an idempotency conflict, and `503` means paid-request capacity is unavailable.</p></article></div>
        </section>
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
          <div className="section-heading"><div><h2 id="evidence-title">One action. Three checks.</h2></div><p>These checks produce one deterministic result. If a data source fails, the result says so.</p></div>
          <EvidenceBento />
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
    const frame = window.requestAnimationFrame(() => {
      scrollToRouteTarget(routeLocation.hash.slice(1));
    });
    return () => window.cancelAnimationFrame(frame);
  }, [routeLocation.pathname, routeLocation.hash]);

  return routeLocation.pathname === "/docs" ? <DocsPage /> : routeLocation.pathname === "/api" ? <ApiPage search={routeLocation.search} /> : <LandingPage />;
}

export default App;
