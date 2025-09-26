import {
  defineConfig,
  presetTypography,
  presetWebFonts,
  presetWind3,
} from "unocss";

export default defineConfig({
  presets: [presetWind3(), presetTypography(), presetWebFonts()],
});
