import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import Image from 'next/image';
import { appName, gitConfig, kubewafDocsRoute } from './shared';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <>
          <Image
            src="/logo-icon.svg"
            alt="kubeWAF"
            width={28}
            height={28}
            className="rounded-sm"
            priority
          />
          <span className="font-semibold tracking-tight">{appName}</span>
        </>
      ),
      url: kubewafDocsRoute,
    },
    githubUrl: `https://github.com/${gitConfig.user}/${gitConfig.repo}`,
    links: [
      {
        text: 'kubeWAF',
        url: kubewafDocsRoute,
        active: 'nested-url',
      },
      {
        text: 'modsecurity-proxy-wasm',
        url: '/docs/modsecurity-proxy-wasm',
        active: 'nested-url',
      },
      {
        text: 'pow-proxy-wasm',
        url: '/docs/pow-proxy-wasm',
        active: 'nested-url',
      },
      {
        text: 'Website',
        url: 'https://kubewaf.io',
        external: true,
      },
    ],
  };
}
