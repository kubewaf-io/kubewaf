'use client';

import { Mermaid as FumadocsMermaid } from 'fumadocs-mermaid/ui';
import type { ComponentProps } from 'react';
import { useTheme } from 'next-themes';

/**
 * Mermaid diagrams via fumadocs-mermaid (same stack as Gryt docs).
 * https://github.com/Gryt-chat/docs — client-side mermaid + remarkMdxMermaid.
 *
 * Use fenced ```mermaid blocks in MDX; the remark plugin turns them into
 * <Mermaid chart="..." /> which this component renders.
 */

const lightThemeConfig = JSON.stringify({
  theme: 'default',
  config: JSON.stringify({
    themeVariables: {
      darkMode: false,
      background: 'transparent',
      primaryColor: '#eef0fb',
      primaryTextColor: '#171717',
      primaryBorderColor: '#4f46e5',
      lineColor: '#64748b',
      secondaryColor: '#f8fafc',
      tertiaryColor: '#f1f5f9',
      fontFamily: 'inherit',
      fontSize: '14px',
      nodeBorder: '#4f46e5',
      nodeTextColor: '#171717',
      mainBkg: '#eef0fb',
      clusterBkg: '#f8fafc',
      clusterBorder: '#cbd5e1',
      edgeLabelBackground: '#ffffff',
      signalColor: '#171717',
      actorBorder: '#4f46e5',
      actorBkg: '#eef0fb',
      actorTextColor: '#171717',
    },
  }),
});

const darkThemeConfig = JSON.stringify({
  theme: 'dark',
  config: JSON.stringify({
    themeVariables: {
      darkMode: true,
      background: 'transparent',
      primaryColor: '#312e81',
      primaryTextColor: '#e2e8f0',
      primaryBorderColor: '#818cf8',
      lineColor: '#64748b',
      secondaryColor: '#1e293b',
      tertiaryColor: '#0f172a',
      fontFamily: 'inherit',
      fontSize: '14px',
      nodeBorder: '#818cf8',
      nodeTextColor: '#e2e8f0',
      mainBkg: '#312e81',
      clusterBkg: '#0f172a',
      clusterBorder: '#334155',
      edgeLabelBackground: '#0f172a',
      signalColor: '#e2e8f0',
      actorBorder: '#818cf8',
      actorBkg: '#1e293b',
      actorTextColor: '#e2e8f0',
    },
  }),
});

export function Mermaid(props: ComponentProps<typeof FumadocsMermaid>) {
  const { resolvedTheme } = useTheme();
  const isDark = resolvedTheme === 'dark';

  return (
    <FumadocsMermaid
      {...props}
      theme={props.theme ?? (isDark ? 'dark' : 'default')}
      config={props.config ?? (isDark ? darkThemeConfig : lightThemeConfig)}
      themeCSS={props.themeCSS ?? 'margin: 1.5rem auto 0;'}
    />
  );
}
