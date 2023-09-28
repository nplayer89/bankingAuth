package service

import (
	"bankingAuth/domain"
	"bankingAuth/dto"
	"bankingAuth/errs"
)

type AuthService interface {
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
}

type DefaultAuthService struct {
	repo            domain.AuthRepository
	RolePermissions domain.RolePermissions
}

func NewLoginService(repo domain.AuthRepository, permissions domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{repo, permissions}
}
