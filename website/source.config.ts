import { defineConfig, defineDocs } from 'fumadocs-mdx/config';
import { metaSchema, pageSchema } from 'fumadocs-core/source/schema';
import { remarkMdxMermaid } from 'fumadocs-mermaid';

// Three product roots under content/docs/{kubewaf,modsecurity-proxy-wasm,pow-proxy-wasm}
// each with meta.json { "root": true }.
export const docs = defineDocs({
  dir: 'content/docs',
  docs: {
    schema: pageSchema,
    postprocess: {
      includeProcessedMarkdown: true,
    },
  },
  meta: {
    schema: metaSchema,
  },
});

export default defineConfig({
  mdxOptions: {
    // Convert ```mermaid fences → <Mermaid chart="..." /> (Gryt/fumadocs-mermaid)
    remarkPlugins: [remarkMdxMermaid],
  },
});
