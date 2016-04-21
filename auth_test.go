package jwt

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/test"
)

func TestJwtAuth(t *testing.T) {

	app := echo.New()

	auth := New(Options{
		SignKey: []byte("test"),
		VerifyKey: []byte("test"),
	})
	originSignMethod := auth.Options.SigningMethod
	claims := Claims{}.SetExpiryIn(time.Second).Set("name", "admin")
	_, tokenStr, err := auth.GenerateToken(claims)

	req := test.NewRequest(echo.GET, "/", nil)
	resp := test.NewResponseRecorder()
	ctx := echo.NewContext(req, resp, app)

	verify := auth.Verify(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})

	// Correct Authorization header
	req.Header().Set(echo.HeaderAuthorization, "Bearer "+tokenStr)

	err = verify(ctx)
	if err != nil {
		t.Errorf(`auth.CheckJwt(%v) == %v`, ctx, err)
	}
	claims2 := ctx.Get(auth.Options.UserProperty)

	if claims2 == nil {
		t.Errorf("Cannot get claims from context with key \"user\"")
	}
	if c, ok := claims2.(map[string]interface{}); !ok {
		t.Errorf("User info fetched from context is not Claims: %s", c)
	}

	if name, ok := claims2.(map[string]interface{})["name"]; !ok || name != "admin" {
		t.Errorf("Claims info is not right", claims2)
	}

	// Empty Authorization header
	req.Header().Set(echo.HeaderAuthorization, "")
	err = verify(ctx)
	if err == nil {
		t.Errorf(`Empty Authorization header test should get emptyTokenErr`)
	}

	// Error Authorization format header
	req.Header().Set(echo.HeaderAuthorization, "test")
	err = auth.CheckJwt(ctx)
	if err == nil {
		t.Errorf(`Wrong Authorization format header test should not pass`)
	}

	if httpError, ok := err.(*echo.HTTPError); ok && httpError.Code != http.StatusUnauthorized {
		t.Errorf("Status code is :%d instead of %d", httpError.Code, http.StatusUnauthorized)
	}

	// Error jwt Authorization header
	req.Header().Set(echo.HeaderAuthorization, "Bearer test")
	err = verify(ctx)
	if err == nil {
		t.Errorf(`Wrong Jwt Authorization header test should not pass`)
	}

	if !strings.HasPrefix(err.Error(), "Error parsing token") {
		t.Errorf("Not token parse Error")
	}

	if httpError, ok := err.(*echo.HTTPError); ok && httpError.Code != http.StatusUnauthorized {
		t.Errorf("Status code is :%d instead of %d", httpError.Code, http.StatusUnauthorized)
	}

	// Error Sign method format header
	auth.Options.SigningMethod = jwt.GetSigningMethod("none")
	req.Header().Set(echo.HeaderAuthorization, "Bearer "+tokenStr)
	err = verify(ctx)
	if err == nil {
		t.Errorf(`Wrong Sign Method test should not pass`)
	}

	if httpError, ok := err.(*echo.HTTPError); ok && httpError.Code != http.StatusUnauthorized {
		t.Errorf("Status code is :%d instead of %d", httpError.Code, http.StatusUnauthorized)
	}

	if !strings.HasPrefix(err.Error(), "Error validating token algorithm") {
		t.Errorf("Not algorithm Error: %s", err)
	}

	auth.Options.SigningMethod = originSignMethod
	auth.Options.IsTokenInvoked = func(token string) bool {
		return true
	}
	req.Header().Set(echo.HeaderAuthorization, "Bearer "+tokenStr)
	err = verify(ctx)
	if err == nil {
		t.Errorf(`Invoked token test should not pass`)
	}

	if httpError, ok := err.(*echo.HTTPError); ok && httpError.Code != http.StatusUnauthorized {
		t.Errorf("Status code is :%d instead of %d", httpError.Code, http.StatusUnauthorized)
	}

	if !strings.Contains(err.Error(), "invoked") {
		t.Errorf("Not token invoke error: %s", err)
	}
}
