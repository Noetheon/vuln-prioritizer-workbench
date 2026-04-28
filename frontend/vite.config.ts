import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  base: "/static/app/",
  plugins: [react(), tailwindcss(), workbenchAppDevPath()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8000"
    }
  },
  build: {
    outDir: "../src/vuln_prioritizer/web/static/app",
    emptyOutDir: true
  }
});

function workbenchAppDevPath(): Plugin {
  return {
    name: "workbench-app-dev-path",
    apply: "serve",
    configureServer(server) {
      server.middlewares.use((request, _response, next) => {
        if ((request.method === "GET" || request.method === "HEAD") && request.url) {
          const [pathname, query = ""] = request.url.split("?");
          if (pathname === "/app" || pathname.startsWith("/app/")) {
            request.url = `/static${pathname}${query ? `?${query}` : ""}`;
          }
        }
        next();
      });
    }
  };
}
