package repositories

import (
	"errors"
	"scale/models"
	"sync"
)

type UserStore interface {
	Add(name string, user models.User) error
	Get(name string) (models.User, error)
	List() (map[string]models.User, error)
	Remove(name string) error
}

type InMemoryUserStore struct {
	mu    sync.RWMutex
	users map[string]models.User
}

func NewInMemoryUserStore() *InMemoryUserStore {
	return &InMemoryUserStore{
		users: make(map[string]models.User),
	}
}

func (s *InMemoryUserStore) Add(name string, user models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[name]; exists {
		return errors.New("user already exists")
	}
	s.users[name] = user
	return nil
}

func (s *InMemoryUserStore) Get(name string) (models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, exists := s.users[name]
	if !exists {
		return models.User{}, errors.New("user not found")
	}
	return user, nil
}

func (s *InMemoryUserStore) List() (map[string]models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copy := make(map[string]models.User, len(s.users))
	for k, v := range s.users {
		copy[k] = v
	}
	return copy, nil
}

func (s *InMemoryUserStore) Remove(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[name]; !exists {
		return errors.New("user not found")
	}
	delete(s.users, name)
	return nil
}
