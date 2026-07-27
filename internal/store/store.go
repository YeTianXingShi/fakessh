package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	MaxUsernameBytes = 256
	MaxPasswordBytes = 1024
	MaxClientBytes   = 512
)

type Attempt struct {
	Username      []byte
	Password      []byte
	Method        string
	RemoteIP      string
	RemotePort    int
	ClientVersion []byte
	At            time.Time
}

type Store struct{ db *sql.DB }

func Open(ctx context.Context, path string) (*Store, error) {
	dsn := path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error                   { return s.db.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS credentials (
  id INTEGER PRIMARY KEY,
  username BLOB NOT NULL,
  password BLOB NOT NULL,
  username_hash BLOB NOT NULL,
  password_hash BLOB NOT NULL,
  username_truncated INTEGER NOT NULL DEFAULT 0,
  password_truncated INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  UNIQUE(username_hash, password_hash)
);
CREATE INDEX IF NOT EXISTS credentials_last_seen_idx ON credentials(last_seen DESC, id DESC);
CREATE TABLE IF NOT EXISTS sources (
  credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  remote_port INTEGER NOT NULL,
  auth_method TEXT NOT NULL,
  client_version BLOB NOT NULL,
  client_hash BLOB NOT NULL,
  client_truncated INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  PRIMARY KEY(credential_id, ip, auth_method, client_hash)
);
CREATE INDEX IF NOT EXISTS sources_last_seen_idx ON sources(last_seen DESC);
CREATE INDEX IF NOT EXISTS sources_ip_idx ON sources(ip);
CREATE TABLE IF NOT EXISTS trend_buckets (
  bucket TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL
);`
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

func (s *Store) Record(ctx context.Context, a Attempt) error {
	if a.At.IsZero() {
		a.At = time.Now().UTC()
	}
	a.At = a.At.UTC()
	if net.ParseIP(a.RemoteIP) == nil {
		return fmt.Errorf("invalid remote IP %q", a.RemoteIP)
	}
	if a.Method != "password" && a.Method != "keyboard-interactive" {
		return fmt.Errorf("invalid authentication method %q", a.Method)
	}

	username, userTruncated := truncate(a.Username, MaxUsernameBytes)
	password, passwordTruncated := truncate(a.Password, MaxPasswordBytes)
	client, clientTruncated := truncate(a.ClientVersion, MaxClientBytes)
	userHash, passwordHash, clientHash := sha256.Sum256(a.Username), sha256.Sum256(a.Password), sha256.Sum256(a.ClientVersion)
	// Fixed-width fractions keep lexical TEXT ordering chronological.
	timestamp := a.At.Format("2006-01-02T15:04:05.000000000Z07:00")
	bucket := a.At.Truncate(time.Hour).Format(time.RFC3339)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO credentials
 (username,password,username_hash,password_hash,username_truncated,password_truncated,first_seen,last_seen,attempts)
 VALUES(?,?,?,?,?,?,?,?,1)
 ON CONFLICT(username_hash,password_hash) DO UPDATE SET
 first_seen=min(first_seen,excluded.first_seen), last_seen=max(last_seen,excluded.last_seen), attempts=attempts+1`,
		username, password, userHash[:], passwordHash[:], userTruncated, passwordTruncated, timestamp, timestamp)
	if err != nil {
		return fmt.Errorf("upsert credential: %w", err)
	}
	var credentialID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM credentials WHERE username_hash=? AND password_hash=?`, userHash[:], passwordHash[:]).Scan(&credentialID); err != nil {
		return fmt.Errorf("find credential: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO sources
 (credential_id,ip,remote_port,auth_method,client_version,client_hash,client_truncated,first_seen,last_seen,attempts)
 VALUES(?,?,?,?,?,?,?,?,?,1)
 ON CONFLICT(credential_id,ip,auth_method,client_hash) DO UPDATE SET
 remote_port=excluded.remote_port, first_seen=min(first_seen,excluded.first_seen),
 last_seen=max(last_seen,excluded.last_seen), attempts=attempts+1`, credentialID, a.RemoteIP, a.RemotePort,
		a.Method, client, clientHash[:], clientTruncated, timestamp, timestamp)
	if err != nil {
		return fmt.Errorf("upsert source: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO trend_buckets(bucket,attempts) VALUES(?,1)
 ON CONFLICT(bucket) DO UPDATE SET attempts=attempts+1`, bucket)
	if err != nil {
		return fmt.Errorf("upsert trend: %w", err)
	}
	return tx.Commit()
}

func truncate(value []byte, maximum int) ([]byte, int) {
	if len(value) <= maximum {
		return value, 0
	}
	return value[:maximum], 1
}

type Stats struct {
	TotalAttempts     int64
	UniqueCredentials int64
	UniqueIPs         int64
	Trend             []Rank
	TopUsers          []Rank
	TopPasswords      []Rank
	TopIPs            []Rank
}

type Rank struct {
	Label string
	Count int64
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var out Stats
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(sum(attempts),0), count(*) FROM credentials`).Scan(&out.TotalAttempts, &out.UniqueCredentials)
	if err != nil {
		return out, err
	}
	if err = s.db.QueryRowContext(ctx, `SELECT count(DISTINCT ip) FROM sources`).Scan(&out.UniqueIPs); err != nil {
		return out, err
	}
	if out.Trend, err = s.ranks(ctx, `SELECT bucket,attempts FROM trend_buckets ORDER BY bucket DESC LIMIT 24`); err != nil {
		return out, err
	}
	if out.TopUsers, err = s.blobRanks(ctx, `SELECT username,sum(attempts) FROM credentials GROUP BY username_hash ORDER BY sum(attempts) DESC LIMIT 10`); err != nil {
		return out, err
	}
	if out.TopPasswords, err = s.blobRanks(ctx, `SELECT password,sum(attempts) FROM credentials GROUP BY password_hash ORDER BY sum(attempts) DESC LIMIT 10`); err != nil {
		return out, err
	}
	if out.TopIPs, err = s.ranks(ctx, `SELECT ip,sum(attempts) FROM sources GROUP BY ip ORDER BY sum(attempts) DESC LIMIT 10`); err != nil {
		return out, err
	}
	for left, right := 0, len(out.Trend)-1; left < right; left, right = left+1, right-1 {
		out.Trend[left], out.Trend[right] = out.Trend[right], out.Trend[left]
	}
	return out, nil
}

func (s *Store) ranks(ctx context.Context, query string) ([]Rank, error) {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Rank
	for rows.Next() {
		var rank Rank
		if err := rows.Scan(&rank.Label, &rank.Count); err != nil {
			return nil, err
		}
		result = append(result, rank)
	}
	return result, rows.Err()
}

func (s *Store) blobRanks(ctx context.Context, query string) ([]Rank, error) {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Rank
	for rows.Next() {
		var value []byte
		var count int64
		if err := rows.Scan(&value, &count); err != nil {
			return nil, err
		}
		result = append(result, Rank{DisplayBytes(value), count})
	}
	return result, rows.Err()
}

type AttemptFilter struct {
	Username, Password, IP, Method, Client string
	Page, PageSize                         int
}
type Credential struct {
	ID                                   int64
	Username, Password                   string
	UsernameTruncated, PasswordTruncated bool
	FirstSeen, LastSeen                  time.Time
	Attempts                             int64
	Sources                              int64
}
type CredentialPage struct {
	Items          []Credential
	Page, PageSize int
	Total          int64
}

func (s *Store) Credentials(ctx context.Context, f AttemptFilter) (CredentialPage, error) {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 {
		f.PageSize = 50
	}
	if f.PageSize > 200 {
		f.PageSize = 200
	}
	where, args := credentialWhere(f)
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM credentials c `+where, args...).Scan(&total); err != nil {
		return CredentialPage{}, err
	}
	query := `SELECT c.id,c.username,c.password,c.username_truncated,c.password_truncated,c.first_seen,c.last_seen,c.attempts,
 (SELECT count(*) FROM sources s WHERE s.credential_id=c.id) FROM credentials c ` + where + ` ORDER BY c.last_seen DESC,c.id DESC LIMIT ? OFFSET ?`
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return CredentialPage{}, err
	}
	defer rows.Close()
	page := CredentialPage{Page: f.Page, PageSize: f.PageSize, Total: total}
	for rows.Next() {
		var c Credential
		var user, pass []byte
		var ut, pt int
		var first, last string
		if err := rows.Scan(&c.ID, &user, &pass, &ut, &pt, &first, &last, &c.Attempts, &c.Sources); err != nil {
			return page, err
		}
		c.Username, c.Password = DisplayBytes(user), DisplayBytes(pass)
		c.UsernameTruncated, c.PasswordTruncated = ut != 0, pt != 0
		c.FirstSeen, _ = time.Parse(time.RFC3339Nano, first)
		c.LastSeen, _ = time.Parse(time.RFC3339Nano, last)
		page.Items = append(page.Items, c)
	}
	return page, rows.Err()
}

func credentialWhere(f AttemptFilter) (string, []any) {
	var clauses []string
	var args []any
	if f.Username != "" {
		clauses = append(clauses, `instr(CAST(c.username AS TEXT),?)>0`)
		args = append(args, f.Username)
	}
	if f.Password != "" {
		clauses = append(clauses, `instr(CAST(c.password AS TEXT),?)>0`)
		args = append(args, f.Password)
	}
	if f.IP != "" {
		clauses = append(clauses, `EXISTS(SELECT 1 FROM sources s WHERE s.credential_id=c.id AND instr(s.ip,?)>0)`)
		args = append(args, f.IP)
	}
	if f.Method != "" {
		clauses = append(clauses, `EXISTS(SELECT 1 FROM sources s WHERE s.credential_id=c.id AND s.auth_method=?)`)
		args = append(args, f.Method)
	}
	if f.Client != "" {
		clauses = append(clauses, `EXISTS(SELECT 1 FROM sources s WHERE s.credential_id=c.id AND instr(CAST(s.client_version AS TEXT),?)>0)`)
		args = append(args, f.Client)
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

type Source struct {
	CredentialID                                  int64
	Username, Password, IP, Method, ClientVersion string
	RemotePort                                    int
	ClientTruncated                               bool
	FirstSeen, LastSeen                           time.Time
	Attempts                                      int64
}

func (s *Store) Sources(ctx context.Context, credentialID int64, page, pageSize int) ([]Source, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > 200 {
		pageSize = 200
	}
	where := ""
	var args []any
	if credentialID > 0 {
		where = " WHERE s.credential_id=?"
		args = append(args, credentialID)
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sources s`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT s.credential_id,c.username,c.password,s.ip,s.remote_port,s.auth_method,s.client_version,s.client_truncated,s.first_seen,s.last_seen,s.attempts
 FROM sources s JOIN credentials c ON c.id=s.credential_id` + where + ` ORDER BY s.last_seen DESC LIMIT ? OFFSET ?`
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var result []Source
	for rows.Next() {
		var x Source
		var u, p, v []byte
		var ct int
		var first, last string
		if err := rows.Scan(&x.CredentialID, &u, &p, &x.IP, &x.RemotePort, &x.Method, &v, &ct, &first, &last, &x.Attempts); err != nil {
			return nil, 0, err
		}
		x.Username = DisplayBytes(u)
		x.Password = DisplayBytes(p)
		x.ClientVersion = DisplayBytes(v)
		x.ClientTruncated = ct != 0
		x.FirstSeen, _ = time.Parse(time.RFC3339Nano, first)
		x.LastSeen, _ = time.Parse(time.RFC3339Nano, last)
		result = append(result, x)
	}
	return result, total, rows.Err()
}

func DisplayBytes(value []byte) string {
	printable := true
	for _, b := range value {
		if b < 0x20 || b == 0x7f {
			printable = false
			break
		}
	}
	if printable && strings.ToValidUTF8(string(value), "\uFFFD") == string(value) {
		return string(value)
	}
	var b strings.Builder
	for _, c := range value {
		if c >= 0x20 && c < 0x7f && c != '\\' {
			b.WriteByte(c)
		} else {
			b.WriteString(`\x`)
			b.WriteString(fmt.Sprintf("%02x", c))
		}
	}
	return b.String()
}

func ParsePage(value string, fallback int) int {
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

var ErrNotFound = errors.New("not found")
