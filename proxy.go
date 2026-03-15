package main

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

var stripResponseHeaders = []string{
	"Set-Cookie",
	"Server",
	"X-Powered-By",
}

var proxyTransport = &http.Transport{
	ResponseHeaderTimeout: 10 * time.Second,
	IdleConnTimeout:       30 * time.Second,
	TLSHandshakeTimeout:   5 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

func newProxy() http.Handler {
	if cfg.GatewayURL == "" {
		return http.NotFoundHandler()
	}
	target, err := url.Parse(cfg.GatewayURL)
	if err != nil {
		slog.Error("invalid GATEWAY_URL", "error", err)
		os.Exit(1)
	}

	rp := &httputil.ReverseProxy{
		Transport: proxyTransport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.URL.Path = strings.TrimPrefix(pr.In.URL.Path, "/control")
			if pr.Out.URL.Path == "" {
				pr.Out.URL.Path = "/"
			}
			pr.Out.Host = target.Host

			pr.Out.Header.Del("Cookie")
			pr.Out.Header.Del("Authorization")

			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Forwarded-Proto")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Real-IP")
			pr.Out.Header.Del("Forwarded")

			pr.SetXForwarded()
		},
		ModifyResponse: func(resp *http.Response) error {
			for _, h := range stripResponseHeaders {
				resp.Header.Del(h)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("proxy upstream error", "error", err)
			badGateway(w)
		},
	}
	return rp
}

func badGateway(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	w.Write([]byte(`{"error":"Bad Gateway"}`))
}
