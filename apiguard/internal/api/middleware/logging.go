package middleware

import (
	"net"
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
)

// RequestLogger returns a middleware that logs each HTTP request using zerolog.
// trustedProxies is the list of upstream proxy CIDRs whose X-Forwarded-For
// and X-Real-IP headers should be trusted when determining the real client IP.
// Pass nil to always use r.RemoteAddr (safe default).
// proxyDepth controls depth-based XFF stripping (see ClientIPFromRequestWithDepth);
// values < 1 are treated as 1.
func RequestLogger(logger zerolog.Logger, trustedProxies []*net.IPNet, proxyDepth ...int) func(next http.Handler) http.Handler {
	depth := 1
	if len(proxyDepth) > 0 && proxyDepth[0] > 1 {
		depth = proxyDepth[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)

			defer func() {
				logger.Info().
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Str("client_ip", ClientIPFromRequestWithDepth(r, trustedProxies, depth)).
					Str("request_id", chimw.GetReqID(r.Context())).
					Int("status", ww.Status()).
					Int("bytes", ww.BytesWritten()).
					Dur("duration", time.Since(start)).
					Msg("request completed")
			}()

			next.ServeHTTP(ww, r)
		})
	}
}
