package repositories

import "scale/models"

type UserStore interface {
	Add(name string, user models.User) error
	Get(name string) (models.User, error)
	List() (map[string]models.User, error)
	Remove(name string) error
}
