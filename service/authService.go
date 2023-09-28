package service

import (
	"bankingAuth/domain"
	"bankingAuth/dto"
	"bankingAuth/errs"
	"bankingAuth/logger"
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

type AuthService interface {
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Refresh(request dto.RefreshTokenRequest) (*dto.LoginResponse, *errs.AppError)
	Verify(urlParams map[string]string) *errs.AppError
}

type DefaultAuthService struct {
	repo            domain.AuthRepository
	RolePermissions domain.RolePermissions
}

func (s DefaultAuthService) Login(req dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) {
	var appErr *errs.AppError
	var login *domain.Login

	if login, appErr = s.repo.FindBy(req.Username, req.Password); appErr != nil {
		return nil, appErr
	}

	claims := login.ClaimForAccessToken()
	authToken := domain.NewAuthToken(claims)

	var accessToken, refreshToken string
	if accessToken, appErr = authToken.NewAccessToken(); appErr != nil {
		return nil, appErr
	}

	if refreshToken, appErr = s.repo.GenerateAndSaveRefreshTokenToStore(authToken); appErr != nil {
		return nil, appErr
	}

	return &dto.LoginResponse{AccessToken: accessToken, RefreshToken: refreshToken}, nil

}

func (s DefaultAuthService) Refresh(request dto.RefreshTokenRequest) (*dto.LoginResponse, *errs.AppError) {
	if vErr := request.IsAccessTokenValid(); vErr != nil {
		if vErr.Errors == jwt.ValidationErrorExpired {
			var appErr *errs.AppError
			if appErr = s.repo.RefreshTokenExists(request.RefreshToken); appErr != nil {
				return nil, appErr
			}
			var accessToken string
			if accessToken, appErr = domain.NewAccessTokenFromRefreshToken(request.RefreshToken); appErr != nil {
				return nil, appErr
			}
			return &dto.LoginResponse{AccessToken: accessToken}, nil
		}
		return nil, errs.NewAuthenticationError("invalid token")
	}
	return nil, errs.NewAuthenticationError("cannot generate a new access token until the curent one expires")
}

func (s DefaultAuthService) Verify(urlParams map[string]string) *errs.AppError {
	if jwtToken, err := jwtTokenFromString(urlParams["token"]); err != nil {
		return errs.NewAuthorizationError(err.Error())
	} else {
		if jwtToken.Valid {
			claims := jwtToken.Claims.(*domain.AccessTokenClaims)
			if claims.IsUserRole() {
				if !claims.IsRequestVerifiedWithTokenClaims(urlParams) {
					return errs.NewAuthenticationError("request not verified with the token claims")
				}
			}
			isAuthorized := s.RolePermissions.IsAuthorizedFor(claims.Role, urlParams["routeName"])
			if !isAuthorized {
				return errs.NewAuthorizationError(fmt.Sprintf("%s role is not authorized", claims.Role))
			}
			return nil
		} else {
			return errs.NewAuthorizationError("Invalid token")
		}
	}
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		return nil, err
	}
	return token, nil
}

func NewLoginService(repo domain.AuthRepository, permissions domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{repo, permissions}
}
