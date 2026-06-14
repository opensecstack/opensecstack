package user

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrNotFound    = errors.New("user: not found")
	ErrDuplicate   = errors.New("user: username or email already taken")
	ErrBadPassword = errors.New("user: invalid password")
)

type User struct {
	ID            string
	Username      string
	Email         string
	EmailVerified bool
	DisplayName   string
	AvatarURL     string
	PasswordHash  string
	Roles         []string
	DeactivatedAt *string
}

type Service struct {
	store      *Store
	bcryptCost int
}

func NewService(store *Store, bcryptCost int) *Service {
	return &Service{store: store, bcryptCost: bcryptCost}
}

func (s *Service) GetByUsername(ctx context.Context, username string) (*User, error) {
	return s.store.GetByUsername(ctx, username)
}

func (s *Service) GetByID(ctx context.Context, id string) (*User, error) {
	return s.store.GetByID(ctx, id)
}

func (s *Service) Authenticate(ctx context.Context, username, password string) (*User, error) {
	// Login forms (and the OAuth auto-login after registration) commonly submit
	// an email address in the username field, while the stored username may be a
	// derived handle (e.g. the email local-part). Accept either identifier.
	u, err := s.store.GetByUsername(ctx, username)
	if err != nil {
		if strings.Contains(username, "@") {
			u, err = s.store.GetByEmail(ctx, username)
		}
		if err != nil {
			return nil, ErrBadPassword
		}
	}
	if u.DeactivatedAt != nil {
		return nil, errors.New("account deactivated")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, ErrBadPassword
	}
	return u, nil
}

func (s *Service) HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost)
	return string(b), err
}

func (s *Service) Create(ctx context.Context, username, email, password, displayName string) (*User, error) {
	hash, err := s.HashPassword(password)
	if err != nil {
		return nil, err
	}
	u := &User{
		Username:    username,
		Email:       email,
		PasswordHash: hash,
		DisplayName: displayName,
	}
	if err := s.store.Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Service) List(ctx context.Context) ([]User, error) {
	return s.store.List(ctx)
}

func (s *Service) Deactivate(ctx context.Context, id string) error {
	return s.store.Deactivate(ctx, id)
}

func (s *Service) GetByEmail(ctx context.Context, email string) (*User, error) {
	return s.store.GetByEmail(ctx, email)
}

func (s *Service) GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Service) StoreVerificationToken(ctx context.Context, userID, token string) error {
	return s.store.StoreVerificationToken(ctx, userID, token)
}

func (s *Service) ConsumeVerificationToken(ctx context.Context, token string) (string, error) {
	return s.store.ConsumeVerificationToken(ctx, token)
}

func (s *Service) MarkEmailVerified(ctx context.Context, userID string) error {
	return s.store.MarkEmailVerified(ctx, userID)
}

func (s *Service) StorePasswordResetToken(ctx context.Context, userID, token string) error {
	return s.store.StorePasswordResetToken(ctx, userID, token)
}

func (s *Service) ConsumePasswordResetToken(ctx context.Context, token string) (string, error) {
	return s.store.ConsumePasswordResetToken(ctx, token)
}

func (s *Service) UpdatePassword(ctx context.Context, userID, hash string) error {
	return s.store.UpdatePassword(ctx, userID, hash)
}

func (s *Service) FindOrCreateBySocial(ctx context.Context, provider, socialID, email, displayName, avatarURL string) (*User, error) {
	return s.store.FindOrCreateBySocial(ctx, provider, socialID, email, displayName, avatarURL)
}
