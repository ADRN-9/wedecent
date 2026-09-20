package coreapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/account"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

var (
	ErrAccountNotConfigured = errors.New("account sign-in is not configured")
	ErrAccountOperation     = errors.New("account operation failed")
)

type AccountClient interface {
	Login(context.Context, string, string, string, string) (*account.Session, error)
	EnsureFresh(context.Context, *account.Session, time.Duration) (*account.Session, bool, error)
	Logout(context.Context, *account.Session) error
}

type AccountServiceConfig struct {
	Client         AccountClient
	SupabaseURL    string
	PublishableKey string
	SessionPath    string
	Status         *ReadService
	InitialSession *account.Session
}

type AccountService struct {
	mu             sync.Mutex
	client         AccountClient
	supabaseURL    string
	publishableKey string
	sessionPath    string
	status         *ReadService
	session        *account.Session
}

func NewAccountService(cfg AccountServiceConfig) (*AccountService, error) {
	if cfg.Client == nil {
		return nil, errors.New("account client is required")
	}
	if strings.TrimSpace(cfg.SessionPath) == "" {
		return nil, errors.New("account session path is required")
	}
	if cfg.Status == nil {
		return nil, errors.New("account status service is required")
	}
	if err := cfg.Status.SetAccountSession(cfg.InitialSession); err != nil {
		return nil, err
	}
	return &AccountService{
		client:         cfg.Client,
		supabaseURL:    strings.TrimSpace(cfg.SupabaseURL),
		publishableKey: strings.TrimSpace(cfg.PublishableKey),
		sessionPath:    cfg.SessionPath,
		status:         cfg.Status,
		session:        cfg.InitialSession,
	}, nil
}

var _ v1.AccountService = (*AccountService)(nil)

func (s *AccountService) SignIn(ctx context.Context, req v1.SignInRequest) (v1.Status, error) {
	if err := ctx.Err(); err != nil {
		return v1.Status{}, err
	}
	email := strings.TrimSpace(req.Email)
	password := req.Password
	req.Password = ""
	defer func() { password = "" }()

	if email == "" || password == "" || len(email) > 320 || len(password) > 4096 {
		return v1.Status{}, fmt.Errorf("%w: invalid credentials", ErrAccountOperation)
	}
	if s.supabaseURL == "" || s.publishableKey == "" {
		return v1.Status{}, ErrAccountNotConfigured
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return v1.Status{}, err
	}

	session, err := s.client.Login(ctx, s.supabaseURL, s.publishableKey, email, password)
	password = ""
	if err != nil {
		return v1.Status{}, fmt.Errorf("%w: login failed", ErrAccountOperation)
	}
	if err := ctx.Err(); err != nil {
		return v1.Status{}, err
	}
	if err := account.Save(s.sessionPath, session); err != nil {
		return v1.Status{}, fmt.Errorf("%w: persist session", ErrAccountOperation)
	}
	if err := s.status.SetAccountSession(session); err != nil {
		_ = account.Delete(s.sessionPath)
		return v1.Status{}, fmt.Errorf("%w: publish account status", ErrAccountOperation)
	}
	s.session = session
	return s.status.GetStatus(ctx)
}

func (s *AccountService) SignOut(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}

	// Remote logout is best-effort, matching the CLI: losing network access must
	// not prevent removal of the protected local session. The remote error is not
	// returned because local sign-out is the user-visible security boundary here.
	if s.session != nil {
		fresh, _, err := s.client.EnsureFresh(ctx, s.session, 0)
		if err == nil {
			_ = s.client.Logout(ctx, fresh)
		}
	}

	if err := account.Delete(s.sessionPath); err != nil {
		return fmt.Errorf("%w: delete session", ErrAccountOperation)
	}
	if err := s.status.SetAccountSession(nil); err != nil {
		return fmt.Errorf("%w: clear account status", ErrAccountOperation)
	}
	s.session = nil
	return nil
}
