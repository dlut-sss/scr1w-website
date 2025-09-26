import { defineConfig } from "astro/config";
import UnoCSS from "unocss/astro";

export default defineConfig({
  site: "https://dlut-sss.github.io",
  integrations: [
    UnoCSS({
      injectReset: true,
    }),
  ],
});
