import Link from 'next/link';
import Image from 'next/image';

const features = [
  {
    title: 'Structured CRDs',
    description:
      'Write SecRule and SecAction as readable Kubernetes YAML — full GitOps, no opaque .conf files.',
  },
  {
    title: 'Composable RuleSets',
    description:
      'Group, reuse, and compose rules across namespaces with automatic resolution and status conditions.',
  },
  {
    title: 'Multi-gateway data plane',
    description:
      'One rule model over ECDS for Envoy Gateway, Istio, and Cilium — only the filter slot differs.',
  },
  {
    title: 'CRS + optional PoW challenge',
    description:
      'Enable OWASP CRS on the WAF CR, and optionally put a proof-of-work challenge in front of evaluation.',
  },
];

const roots = [
  {
    title: 'kubeWAF',
    href: '/docs/kubewaf',
    repo: 'https://github.com/kubewaf-io/kubewaf',
    description: 'Kubernetes operator — CRDs, rules, challenge properties, providers.',
  },
  {
    title: 'modsecurity-proxy-wasm',
    href: '/docs/modsecurity-proxy-wasm',
    repo: 'https://github.com/kubewaf-io/modsecurity-proxy-wasm',
    description: 'ModSecurity Proxy-Wasm engine with embedded OWASP CRS.',
  },
  {
    title: 'pow-proxy-wasm',
    href: '/docs/pow-proxy-wasm',
    repo: 'https://github.com/kubewaf-io/pow-proxy-wasm',
    description: 'Stateless browser proof-of-work challenge filter for Envoy.',
  },
];

export default function HomePage() {
  return (
    <main className="flex flex-1 flex-col">
      <section className="relative overflow-hidden border-b">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-indigo-500/15 via-transparent to-transparent" />
        <div className="relative mx-auto flex max-w-5xl flex-col items-center px-6 py-24 text-center sm:py-32">
          <Image
            src="/logo-icon.svg"
            alt="kubeWAF"
            width={72}
            height={72}
            className="mb-6 drop-shadow-sm"
            priority
          />
          <p className="mb-3 text-sm font-medium tracking-wide text-indigo-600 dark:text-indigo-400">
            Kubernetes-native WAF
          </p>
          <h1 className="max-w-3xl text-4xl font-bold tracking-tight sm:text-5xl">
            Protect workloads with{' '}
            <span className="bg-gradient-to-r from-indigo-600 to-orange-500 bg-clip-text text-transparent">
              ModSecurity-compatible
            </span>{' '}
            rules
          </h1>
          <p className="mt-5 max-w-2xl text-lg text-fd-muted-foreground">
            kubeWAF defines WAF policy as version-controlled Custom Resources and enforces them
            with Wasm inside Envoy — across Envoy Gateway, Istio, and Cilium.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link
              href="/docs/kubewaf"
              className="rounded-full bg-fd-primary px-5 py-2.5 text-sm font-medium text-fd-primary-foreground transition hover:opacity-90"
            >
              kubeWAF docs
            </Link>
            <Link
              href="/docs/kubewaf/getting-started/quickstart"
              className="rounded-full border border-fd-border bg-fd-background px-5 py-2.5 text-sm font-medium transition hover:bg-fd-accent"
            >
              Quick start
            </Link>
            <a
              href="https://github.com/kubewaf-io/kubewaf"
              target="_blank"
              rel="noreferrer"
              className="rounded-full border border-fd-border px-5 py-2.5 text-sm font-medium transition hover:bg-fd-accent"
            >
              GitHub
            </a>
          </div>
          <p className="mt-6 rounded-full border border-amber-500/30 bg-amber-500/10 px-4 py-1.5 text-xs text-amber-800 dark:text-amber-200">
            Alpha software — APIs may change. Feedback and stars welcome!
          </p>
        </div>
      </section>

      <section className="mx-auto w-full max-w-5xl px-6 py-16">
        <h2 className="mb-2 text-center text-2xl font-semibold tracking-tight">
          Three documentation roots
        </h2>
        <p className="mx-auto mb-8 max-w-2xl text-center text-sm text-fd-muted-foreground">
          Each project has its own docs tree and sidebar. kubeWAF is the default.
        </p>
        <div className="grid gap-4 md:grid-cols-3">
          {roots.map((c) => (
            <div
              key={c.title}
              className="flex flex-col rounded-2xl border bg-fd-card p-6 shadow-sm transition hover:border-indigo-500/40 hover:shadow-md"
            >
              <h3 className="text-lg font-semibold">
                <Link href={c.href} className="hover:underline">
                  {c.title}
                </Link>
              </h3>
              <p className="mt-2 flex-1 text-sm leading-relaxed text-fd-muted-foreground">
                {c.description}
              </p>
              <div className="mt-4 flex flex-wrap gap-3 text-sm">
                <Link href={c.href} className="font-medium text-indigo-600 dark:text-indigo-400">
                  Docs →
                </Link>
                <a
                  href={c.repo}
                  target="_blank"
                  rel="noreferrer"
                  className="text-fd-muted-foreground hover:text-fd-foreground"
                >
                  GitHub ↗
                </a>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="border-t bg-fd-secondary/20">
        <div className="mx-auto grid w-full max-w-5xl gap-4 px-6 py-16 sm:grid-cols-2">
          {features.map((feature) => (
            <div
              key={feature.title}
              className="rounded-2xl border bg-fd-card p-6 shadow-sm transition hover:border-indigo-500/40 hover:shadow-md"
            >
              <h2 className="text-lg font-semibold">{feature.title}</h2>
              <p className="mt-2 text-sm leading-relaxed text-fd-muted-foreground">
                {feature.description}
              </p>
            </div>
          ))}
        </div>
      </section>

      <section className="border-t bg-fd-secondary/30">
        <div className="mx-auto flex max-w-5xl flex-col items-start justify-between gap-4 px-6 py-12 sm:flex-row sm:items-center">
          <div>
            <h2 className="text-xl font-semibold">Start protecting services today</h2>
            <p className="mt-1 text-sm text-fd-muted-foreground">
              Helm install, wire ECDS, attach a WAF CR — minutes to first protected path.
            </p>
          </div>
          <Link
            href="/docs/kubewaf/getting-started/installation"
            className="rounded-full bg-fd-primary px-5 py-2.5 text-sm font-medium text-fd-primary-foreground transition hover:opacity-90"
          >
            Installation guide
          </Link>
        </div>
      </section>
    </main>
  );
}
