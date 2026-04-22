package main

import (
	"embed"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Embed the web UI files (only used in production)
//
//go:embed web
var webUI embed.FS

// serveWebUI returns an HTTP handler for serving the web UI.
// In development mode (devMode=true), it proxies to a frontend dev server
// at localhost:3000 for hot module replacement (HMR). Falls back to serving
// from the filesystem if the dev server is not running.
// In production mode (devMode=false), it serves from embedded files.
func serveWebUI(devMode bool) http.Handler {
	if devMode {
		// Development mode: proxy to Vite/Next dev server on :3000,
		// falling back to filesystem serve if the dev server is down.
		slog.Info("web UI in development mode — proxying to localhost:3000 (run 'npm run dev' in cmd/gateway/web)")
		return newDevModeProxy()
	}

	// Production mode: serve from embedded files.
	stripped, err := fs.Sub(webUI, "web")
	if err != nil {
		slog.Warn("failed to create sub filesystem for web UI", "error", err)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Web UI not available", http.StatusNotFound)
		})
	}
	slog.Info("serving web UI from embedded files (production mode)")

	fsRoot := stripped
	fileServer := http.FileServer(http.FS(stripped))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin/") || strings.HasPrefix(r.URL.Path, "/health") {
			http.NotFound(w, r)
			return
		}

		path := r.URL.Path
		if path != "/" && !hasFileExtension(path) {
			if _, err := fs.Stat(fsRoot, strings.TrimPrefix(path, "/")); err != nil {
				if strings.Contains(r.Header.Get("Accept"), "text/html") {
					r.URL.Path = "/"
				} else {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					w.Write([]byte(`{"error":"not_found"}`))
					return
				}
			}
		}

		// 1-year cache for static assets in production.
		if hasFileExtension(path) {
			w.Header().Set("Cache-Control", "public, max-age=31536000")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}

		fileServer.ServeHTTP(w, r)
	})
}

// newDevModeProxy returns a handler that proxies to localhost:3000
// and falls back to serving from the filesystem if the proxy is unavailable.
func newDevModeProxy() http.Handler {
	webDistPath := filepath.Join("cmd", "gateway", "web")
	if _, err := os.Stat(webDistPath); os.IsNotExist(err) {
		slog.Warn("web directory not found — run 'make build-web' or 'npm run dev' in cmd/gateway/web")
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/admin/") || strings.HasPrefix(r.URL.Path, "/health") {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Vanta</title></head>
<body>
	<h1>Development Mode</h1>
	<p>Web UI not built. Choose one of:</p>
	<ol>
		<li><strong>Recommended:</strong> <code>npm run dev</code> in <code>cmd/gateway/web</code> for HMR at localhost:3000</li>
		<li>Or build the UI: <code>make build-web</code></li>
	</ol>
</body>
</html>`))
		})
	}

	proxyMux := http.NewServeMux()

	// Proxy all requests to the Vite dev server.
	proxyMux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin/") || strings.HasPrefix(r.URL.Path, "/health") {
			http.NotFound(w, r)
			return
		}

		// Attempt to proxy to the frontend dev server.
		proxyReq := newProxyRequest(r)
		resp, err := http.DefaultClient.Do(proxyReq)
		if err != nil {
			// Dev server not running — fall back to filesystem.
			slog.Debug("dev server unavailable, falling back to filesystem serve", "error", err)
			serveFromFilesystem(webDistPath).ServeHTTP(w, r)
			return
		}
		defer resp.Body.Close()

		// Copy response headers.
		for k, v := range resp.Header {
			if k == "Content-Length" || k == "Transfer-Encoding" {
				continue
			}
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))

	return proxyMux
}

// serveFromFilesystem returns a handler that serves from the filesystem
// (used as fallback when the dev server is not running).
func serveFromFilesystem(webPath string) http.Handler {
	fsRoot := os.DirFS(webPath)
	fileServer := http.FileServer(http.Dir(webPath))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin/") || strings.HasPrefix(r.URL.Path, "/health") {
			http.NotFound(w, r)
			return
		}

		path := r.URL.Path
		if path != "/" && !hasFileExtension(path) {
			if _, err := fs.Stat(fsRoot, strings.TrimPrefix(path, "/")); err != nil {
				if strings.Contains(r.Header.Get("Accept"), "text/html") {
					r.URL.Path = "/"
				} else {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					w.Write([]byte(`{"error":"not_found"}`))
					return
				}
			}
		}

		// No cache in dev mode.
		if hasFileExtension(path) {
			w.Header().Set("Cache-Control", "no-cache")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}

		fileServer.ServeHTTP(w, r)
	})
}

// newProxyRequest clones r into a new request targeting localhost:3000.
func newProxyRequest(r *http.Request) *http.Request {
	req := &http.Request{
		Method: r.Method,
		URL: &url.URL{
			Scheme: "http",
			Host:   "localhost:3000",
			Path:   r.URL.Path,
		},
		Header:       r.Header.Clone(),
		Body:        r.Body,
		ContentLength: r.ContentLength,
	}
	return req
}

// hasFileExtension checks if a path has a file extension.
func hasFileExtension(path string) bool {
	return strings.Contains(path, ".")
}
