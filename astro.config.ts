import { defineConfig } from "astro/config";
import UnoCSS from "unocss/astro";
import remarkToc from "remark-toc";

export default defineConfig({
  site: "https://dlut-sss.github.io",
  integrations: [
    UnoCSS({
      injectReset: true,
    }),
  ],
  markdown: {
    remarkPlugins: [[remarkToc, { heading: "目录", maxDepth: 3 }]],
  },
});
