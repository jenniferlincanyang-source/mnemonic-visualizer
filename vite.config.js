import { defineConfig } from "vite";

export default defineConfig({
  // GitHub Pages 子路径下资源需要相对路径
  base: "./",
  server: { port: 5173, strictPort: true },
});

