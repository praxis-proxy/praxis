import React, { useState, useRef, useEffect } from 'react';
import Layout from '@theme/Layout';
import { examples, categories, type Category, type Example } from '../../data/examples';
import styles from './index.module.css';

function CodeOverlay({ example, onClose }: { example: Example; onClose: () => void }) {
  const [yaml, setYaml] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const url = `https://raw.githubusercontent.com/praxis-proxy/praxis/main/${example.path}`;
    fetch(url)
      .then((res) => res.text())
      .then(setYaml)
      .catch(() => setYaml('# Could not load this example.\n# View it on GitHub instead.'));
  }, [example.path]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKey);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = '';
    };
  }, [onClose]);

  const handleCopy = async () => {
    if (!yaml) return;
    try {
      await navigator.clipboard.writeText(yaml);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {}
  };

  return (
    <div className={styles.overlay} onClick={onClose} role="dialog" aria-modal="true">
      <div className={styles.overlayPanel} onClick={(e) => e.stopPropagation()}>
        <div className={styles.overlayHeader}>
          <div>
            <span className={styles.overlayName}>{example.name}</span>
            <span className={styles.overlayBadge}>{example.category}</span>
          </div>
          <div className={styles.overlayActions}>
            <a
              className={styles.overlayBtn}
              href={`https://github.com/praxis-proxy/praxis/blob/main/${example.path}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              GitHub
            </a>
            <button className={styles.overlayBtn} onClick={handleCopy}>
              {copied ? '✓ copied' : '⧉ copy'}
            </button>
            <button className={styles.overlayClose} onClick={onClose} aria-label="Close">
              ✕
            </button>
          </div>
        </div>
        <div className={styles.overlayBody}>
          {yaml ? <pre>{yaml}</pre> : <p className={styles.overlayLoading}>Loading...</p>}
        </div>
      </div>
    </div>
  );
}

export default function Examples(): React.JSX.Element {
  const [activeCategory, setActiveCategory] = useState<Category>('All');
  const [selected, setSelected] = useState<Example | null>(null);

  const filtered =
    activeCategory === 'All'
      ? examples
      : examples.filter((e) => e.category === activeCategory);

  const handleSelect = (example: Example) => {
    setSelected(selected?.path === example.path ? null : example);
  };

  return (
    <Layout title="Examples" description="Ready-to-use YAML configurations for Praxis proxy">
      <div className={styles.container}>
        <h1 className={styles.title}>Examples</h1>
        <p className={styles.subtitle}>
          {examples.length} configurations you can copy and run. Each one demonstrates a real use case.
        </p>
        <div className={styles.tabs}>
          {categories.map((cat) => (
            <button
              key={cat}
              className={`${styles.tab} ${activeCategory === cat ? styles.tabActive : ''}`}
              onClick={() => { setActiveCategory(cat); setSelected(null); }}
            >
              {cat}
            </button>
          ))}
        </div>
        <p className={styles.count}>
          Showing {filtered.length} example{filtered.length !== 1 ? 's' : ''}
        </p>
        <div className={styles.grid}>
          {filtered.map((example) => (
            <button
              key={example.path}
              className={`${styles.card} ${selected?.path === example.path ? styles.cardSelected : ''}`}
              onClick={() => handleSelect(example)}
              aria-label={`View ${example.name} configuration`}
            >
              <div className={styles.cardHeader}>
                <span className={styles.cardName}>{example.name}</span>
                <span className={styles.badge}>{example.category}</span>
              </div>
              <p className={styles.cardDesc}>{example.description}</p>
            </button>
          ))}
        </div>

        {selected && (
          <CodeOverlay
            key={selected.path}
            example={selected}
            onClose={() => setSelected(null)}
          />
        )}
      </div>
    </Layout>
  );
}
