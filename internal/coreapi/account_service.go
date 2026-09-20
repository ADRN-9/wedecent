package coreapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"wedecent.com/wedecent/internal/account"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

var (
	ErrAccountNotConfigured = errors.New("account sign-in is not configured")
	ErrAccountOperation     = errors.New("account operation failed")
)

type AccountLoginClient interface {
	Login(context.Context, string, string, string, string) (*account.Session, error)
}

type AccountServiceConfig struct {
	Client         AccountLoginClient
	SupabaseURL    string
	PublishableKey string
	SessionPath    string
	Status         *ReadService
	InitialSession *account.Session
}

type AccountService struct {
	mu             sync.Mutex
	client         AccountLoginClient
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
		return v1.Status{}, fmt.Errorf("%w: %v", ErrAccountOperation, err)
	}
	if err := ctx.Err(); err != nil {
		return v1.Status{}, err
	}
	if err := account.Save(s.sessionPath, session); err != nil {
		return v1.Status{}, fmt.Errorf("%w: persist session: %v", ErrAccountOperation, err)
	}
	if err := s.status.SetAccountSession(session); err != nil {
		_ = account.Delete(s.sessionPath)
		return v1.Status{}, fmt.Errorf("%w: publish account status: %v", ErrAccountOperation, err)
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
	if err := account.Delete(s.sessionPath); err != nil {
		return fmt.Errorf("%w: delete session: %v", ErrAccountOperation, err)
	}
	if err := s.status.SetAccountSession(nil); err != nil {
		return fmt.Errorf("%w: clear account status: %v", ErrAccountOperation, err)
	}
	s.session = nil
	return nil
}
