import { defineConfig } from "vite";

export default defineConfig({
  // Tauri prints its own output next to Vite's; keep the terminal history.
  clearScreen: false,
  build: {
    rollupOptions: {
      onwarn(warning, warn) {
        // lucide-react ships "use client" directives for React Server Components; they mean nothing here.
        if (warning.code === "MODULE_LEVEL_DIRECTIVE" && warning.message.includes('"use client"')) return;
        warn(warning);
      },
    },
  },
});
