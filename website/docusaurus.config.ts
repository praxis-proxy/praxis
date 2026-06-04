import {themes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'Praxis',
  tagline: 'The proxy built for AI infrastructure',
  favicon: 'img/favicon.ico',

  future: {
    v4: true,
  },

  url: 'https://praxis.fast',
  baseUrl: '/',
  organizationName: 'praxis-proxy',
  projectName: 'praxis',
  onBrokenLinks: 'throw',

  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  headTags: [
    {
      tagName: 'link',
      attributes: {
        rel: 'preconnect',
        href: 'https://fonts.googleapis.com',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'preconnect',
        href: 'https://fonts.gstatic.com',
        crossorigin: 'anonymous',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'stylesheet',
        href: 'https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Hanken+Grotesk:wght@300;400;500;600;700&display=swap',
      },
    },
  ],

  presets: [
    [
      'classic',
      {
        docs: {
          path: '../docs',
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/praxis-proxy/praxis/tree/main/',
          exclude: ['proposals/**', 'superpowers/**'],
        },
        blog: {
          showReadingTime: true,
          onInlineAuthors: 'ignore',
          editUrl: 'https://github.com/praxis-proxy/praxis/tree/main/website/',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themes: [
    [
      '@easyops-cn/docusaurus-search-local',
      {
        hashed: true,
        indexBlog: true,
        indexDocs: true,
        docsDir: '../docs',
        docsRouteBasePath: '/docs',
        highlightSearchTermsOnTargetPage: true,
      },
    ],
  ],

  themeConfig: {
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: true,
      respectPrefersColorScheme: false,
    },
    navbar: {
      title: 'Praxis',
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docs',
          position: 'left',
          label: 'Docs',
        },
        {to: '/examples', label: 'Examples', position: 'left'},
        {to: '/blog', label: 'Blog', position: 'left'},
        {
          href: 'https://github.com/praxis-proxy/praxis',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Getting Started',
          items: [
            {label: 'Introduction', to: '/docs/getting-started/introduction'},
            {label: 'Quick Start', to: '/docs/getting-started/quickstart'},
            {label: 'Installation', to: '/docs/getting-started/installation'},
            {label: 'Examples', to: '/examples'},
          ],
        },
        {
          title: 'Documentation',
          items: [
            {label: 'Architecture', to: '/docs/architecture/system-design'},
            {label: 'Configuration', to: '/docs/configuration/overview'},
            {label: 'Filters', to: '/docs/filters/filter-model'},
            {label: 'Protocols', to: '/docs/protocols/tls'},
            {label: 'Security', to: '/docs/security/hardening'},
          ],
        },
        {
          title: 'Community',
          items: [
            {label: 'GitHub', href: 'https://github.com/praxis-proxy/praxis'},
            {label: 'Discussions', href: 'https://github.com/praxis-proxy/praxis/discussions'},
            {label: 'Issues', href: 'https://github.com/praxis-proxy/praxis/issues'},
            {label: 'Contributing', to: '/docs/development/contributing'},
          ],
        },
        {
          title: 'Resources',
          items: [
            {label: 'Blog', to: '/blog'},
            {label: 'Benchmarks', to: '/docs/development/benchmarks'},
            {label: 'Releases', href: 'https://github.com/praxis-proxy/praxis/releases'},
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Praxis Contributors. MIT License.`,
    },
    prism: {
      theme: themes.vsDark,
      darkTheme: themes.vsDark,
      additionalLanguages: ['bash', 'yaml', 'toml', 'rust', 'json'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
