import React, { useState } from 'react';
import Layout from '@theme/Layout';
import styles from './index.module.css';

const features = [
  {
    title: 'AI-Native Routing',
    description:
      'Route LLM requests to the right provider by inspecting JSON bodies. Inject credentials per-cluster so clients never handle API keys.',
    icon: '⇉',
  },
  {
    title: 'Everything is a Filter',
    description:
      '35+ built-in filters you compose into pipelines. Need something custom? Write it in Rust — it compiles into the binary.',
    icon: '≡',
  },
  {
    title: 'Secure by Default',
    description:
      'Zero lines of unsafe code. Rustls instead of OpenSSL. Every security filter — CORS, CSRF, IP ACL, rate limiting — ships ready to use.',
    icon: '△',
  },
  {
    title: 'Any Protocol, Zero Downtime',
    description:
      'HTTP/1.1, HTTP/2, TCP, WebSocket, SSE, gRPC with TLS and mTLS. Swap configs at runtime without dropping a connection.',
    icon: '⬡',
  },
];

function Pipeline() {
  return (
    <div className={styles.pipeline} aria-hidden="true">
      <div className={styles.pipelineLabel}>Filter Pipeline</div>

      <div className={styles.pipelineEntry}>
        <div className={styles.pipelineDot} />
        <span className={styles.pipelineEntryLabel}>incoming request</span>
      </div>

      <div className={styles.pipelineConnector}>
        <div className={styles.flowDot} style={{ animationDelay: '0s' }} />
      </div>

      <div className={styles.filterNode}>
        <div className={styles.filterName}>cors</div>
        <div className={styles.filterDesc}>origin validation</div>
      </div>

      <div className={styles.pipelineConnector}>
        <div className={styles.flowDot} style={{ animationDelay: '0.3s' }} />
      </div>

      <div className={styles.filterNode}>
        <div className={styles.filterName}>rate_limit</div>
        <div className={styles.filterDesc}>token bucket · per_ip</div>
      </div>

      <div className={styles.pipelineConnector}>
        <div className={styles.flowDot} style={{ animationDelay: '0.6s' }} />
      </div>

      <div className={styles.filterNode}>
        <div className={styles.filterName}>model_to_header</div>
        <div className={styles.filterDesc}>extract model → X-Model</div>
      </div>

      <div className={styles.pipelineConnector}>
        <div className={styles.flowDot} style={{ animationDelay: '0.9s' }} />
      </div>

      <div className={styles.filterNode + ' ' + styles.filterNodeAccent}>
        <div className={styles.filterName}>router</div>
        <div className={styles.filterDesc}>match X-Model header</div>
      </div>

      <div className={styles.pipelineBranch}>
        <div className={styles.branchLeft}>
          <div className={styles.branchConnector}>
            <div className={styles.flowDot} style={{ animationDelay: '1.2s' }} />
          </div>
          <div className={styles.filterNodeSmall}>
            <div className={styles.filterName}>openai</div>
            <div className={styles.filterDesc}>credential_injection</div>
          </div>
        </div>
        <div className={styles.branchRight}>
          <div className={styles.branchConnector}>
            <div className={styles.flowDot} style={{ animationDelay: '1.4s' }} />
          </div>
          <div className={styles.filterNodeSmall}>
            <div className={styles.filterName}>anthropic</div>
            <div className={styles.filterDesc}>credential_injection</div>
          </div>
        </div>
      </div>

      <div className={styles.pipelineFooter}>
        <div className={styles.pipelineConnectorCenter}>
          <div className={styles.flowDot} style={{ animationDelay: '1.7s' }} />
        </div>
        <div className={styles.filterNodeSmall}>
          <div className={styles.filterName}>load_balancer</div>
          <div className={styles.filterDesc}>→ upstream</div>
        </div>
      </div>
    </div>
  );
}

function InstallSnippet() {
  const [copied, setCopied] = useState(false);
  const command = 'cargo install praxis';

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback: select text for manual copy
    }
  };

  return (
    <div
      className={styles.installSnippet}
      onClick={handleCopy}
      onKeyDown={(e) => e.key === 'Enter' && handleCopy()}
      role="button"
      tabIndex={0}
      aria-label={`Copy install command: ${command}`}
    >
      <span className={styles.installPrompt}>$</span>
      <code>{command}</code>
      <span className={`${styles.installCopyHint} ${copied ? styles.installCopied : ''}`}>
        {copied ? '✓' : '⧉'}
      </span>
    </div>
  );
}

export default function Home(): React.JSX.Element {
  return (
    <Layout description="High-performance, security-first HTTP proxy and framework for AI and cloud-native workloads.">
      <main>
        <section className={styles.hero}>
          <div className={styles.heroGlow} aria-hidden="true" />
          <div className={styles.heroSplit}>
            <div className={styles.heroContent}>
              <h1 className={styles.heroTitle}>
                The proxy built for<br />
                <span className={styles.heroAccent}>AI infrastructure</span>
              </h1>

              <p className={styles.heroSubtitle}>
                An open-source proxy framework where every behavior is a composable
                filter. Secure by default, extensible in Rust.
              </p>

              <div className={styles.heroCtas}>
                <a className={styles.ctaPrimary} href="/docs/getting-started/introduction">
                  Get Started
                </a>
                <a
                  className={styles.ctaSecondary}
                  href="https://github.com/praxis-proxy/praxis"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  GitHub
                </a>
              </div>

              <InstallSnippet />
            </div>

            <div className={styles.heroVisual}>
              <Pipeline />
            </div>
          </div>

          <div className={styles.heroLine} aria-hidden="true" />
        </section>

        <section className={styles.features}>
          <div className={styles.featuresInner}>
            <h2 className={styles.featuresTitle}>Why teams choose Praxis</h2>
            <div className={styles.featuresGrid}>
              {features.map((feature) => (
                <div key={feature.title} className={styles.featureCard}>
                  <h3 className={styles.featureTitle}>
                    <span className={styles.featureIcon} aria-hidden="true">{feature.icon}</span>
                    {feature.title}
                  </h3>
                  <p className={styles.featureDesc}>{feature.description}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className={styles.ctaSection}>
          <div className={styles.ctaInner}>
            <div>
              <h2 className={styles.ctaSectionTitle}>Open source. Start building.</h2>
              <p className={styles.ctaSectionSub}>
                MIT licensed. From first config to production in minutes.
              </p>
            </div>
            <div className={styles.ctaLinks}>
              <a className={styles.ctaPrimary} href="/docs/getting-started/quickstart">
                Quick Start
              </a>
              <a className={styles.ctaSecondary} href="/examples">
                Examples
              </a>
              <a
                className={styles.ctaSecondary}
                href="https://github.com/praxis-proxy/praxis"
                target="_blank"
                rel="noopener noreferrer"
              >
                GitHub
              </a>
            </div>
          </div>
        </section>
      </main>
    </Layout>
  );
}
