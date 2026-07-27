package web

import (
	"context"
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"fakessh/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Server struct {
	store     *store.Store
	logger    *slog.Logger
	http      *http.Server
	templates *template.Template
}

func New(addr string, dataStore *store.Store, logger *slog.Logger) (*Server, error) {
	functions := template.FuncMap{"time": func(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05 MST") }, "pages": func(total int64, size int) int {
		if size < 1 {
			return 1
		}
		result := int((total + int64(size) - 1) / int64(size))
		if result < 1 {
			return 1
		}
		return result
	}, "dec": func(value int) int { return value - 1 }, "inc": func(value int) int { return value + 1 }, "attemptURL": attemptURL, "sourceURL": sourceURL}
	t, err := template.New("").Funcs(functions).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s := &Server{store: dataStore, logger: logger, templates: t}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.dashboard)
	mux.HandleFunc("GET /attempts", s.attempts)
	mux.HandleFunc("GET /sources", s.sources)
	mux.HandleFunc("GET /healthz", s.health)
	mux.Handle("GET /static/", http.FileServerFS(assets))
	s.http = &http.Server{Addr: addr, Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	return s, nil
}

func (s *Server) ListenAndServe() error {
	s.logger.Info("web dashboard listening", "address", s.http.Addr)
	err := s.http.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
func (s *Server) Handler() http.Handler              { return s.http.Handler }
func (s *Server) Shutdown(ctx context.Context) error { return s.http.Shutdown(ctx) }

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.Stats(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "dashboard.html", map[string]any{"Title": "Dashboard", "Stats": stats})
}
func (s *Server) attempts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AttemptFilter{Username: q.Get("username"), Password: q.Get("password"), IP: q.Get("ip"), Method: q.Get("method"), Client: q.Get("client"), Page: store.ParsePage(q.Get("page"), 1), PageSize: store.ParsePage(q.Get("page_size"), 50)}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 {
		f.PageSize = 50
	}
	if f.PageSize > 200 {
		f.PageSize = 200
	}
	page, err := s.store.Credentials(r.Context(), f)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "attempts.html", map[string]any{"Title": "Credentials", "Result": page, "Filter": f})
}
func (s *Server) sources(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id, _ := strconv.ParseInt(q.Get("credential_id"), 10, 64)
	page := store.ParsePage(q.Get("page"), 1)
	size := store.ParsePage(q.Get("page_size"), 50)
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 50
	}
	if size > 200 {
		size = 200
	}
	items, total, err := s.store.Sources(r.Context(), id, page, size)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "sources.html", map[string]any{"Title": "Sources", "Items": items, "Total": total, "Page": page, "PageSize": size, "CredentialID": id})
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("ok\n"))
}
func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		s.logger.Error("render page", "template", name, "error", err)
	}
}
func (s *Server) fail(w http.ResponseWriter, err error) {
	s.logger.Error("web request failed", "error", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func attemptURL(filter store.AttemptFilter, page int) string {
	values := url.Values{}
	if filter.Username != "" {
		values.Set("username", filter.Username)
	}
	if filter.Password != "" {
		values.Set("password", filter.Password)
	}
	if filter.IP != "" {
		values.Set("ip", filter.IP)
	}
	if filter.Method != "" {
		values.Set("method", filter.Method)
	}
	if filter.Client != "" {
		values.Set("client", filter.Client)
	}
	values.Set("page", strconv.Itoa(page))
	values.Set("page_size", strconv.Itoa(filter.PageSize))
	return "/attempts?" + values.Encode()
}

func sourceURL(credentialID int64, page, pageSize int) string {
	values := url.Values{}
	if credentialID > 0 {
		values.Set("credential_id", strconv.FormatInt(credentialID, 10))
	}
	values.Set("page", strconv.Itoa(page))
	values.Set("page_size", strconv.Itoa(pageSize))
	return "/sources?" + values.Encode()
}
