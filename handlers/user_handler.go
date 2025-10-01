package handlers

import (
	"net/http"
	"scale/internal/models"
	"scale/repositories"

	"github.com/gin-gonic/gin"
	"github.com/gosimple/slug"
)

// UserHandler handles HTTP operations for users
type UserHandler struct {
	Store repositories.UserStore
}

// NewUserHandler creates a new UserHandler
func NewUserHandler(store repositories.UserStore) *UserHandler {
	return &UserHandler{Store: store}
}

// CreateUser handles POST /users
func (h *UserHandler) CreateUser(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id := slug.Make(user.Name)
	if err := h.Store.Add(id, user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"id":     id,
	})
}

// ListUsers handles GET /users
func (h *UserHandler) ListUsers(c *gin.Context) {
	users, err := h.Store.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, users)
}

// GetUser handles GET /users/:id
func (h *UserHandler) GetUser(c *gin.Context) {
	id := c.Param("id")
	user, err := h.Store.Get(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	c.JSON(http.StatusOK, user)
}

// DeleteUser handles DELETE /users/:id
func (h *UserHandler) DeleteUser(c *gin.Context) {
	id := c.Param("id")
	err := h.Store.Remove(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}
