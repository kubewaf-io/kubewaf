import { Inter } from 'next/font/google';
import { Provider } from '@/components/provider';
import { Banner } from 'fumadocs-ui/components/banner';
import type { Metadata } from 'next';
import { appDescription, appName } from '@/lib/shared';
import './global.css';

const inter = Inter({
  subsets: ['latin'],
});

export const metadata: Metadata = {
  title: {
    default: appName,
    template: `%s | ${appName}`,
  },
  description: appDescription,
  metadataBase: new URL('https://kubewaf.io'),
  icons: {
    icon: [
      { url: '/favicon.ico' },
      { url: '/favicon-32x32.png', sizes: '32x32', type: 'image/png' },
      { url: '/favicon-16x16.png', sizes: '16x16', type: 'image/png' },
    ],
    apple: [{ url: '/apple-touch-icon.png' }],
  },
};

export default function Layout({ children }: LayoutProps<'/'>) {
  return (
    <html lang="en" className={inter.className} suppressHydrationWarning>
      <body className="flex min-h-screen flex-col">
        <Banner id="alpha-banner" variant="normal">
          kubeWAF is under active development — feedback and stars on{' '}
          <a
            href="https://github.com/kubewaf-io/kubewaf"
            className="underline underline-offset-2"
            target="_blank"
            rel="noreferrer"
          >
            GitHub
          </a>{' '}
          are very welcome!
        </Banner>
        <Provider>{children}</Provider>
      </body>
    </html>
  );
}
