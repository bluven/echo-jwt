package jwt

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
)

type IsTokenInvoked func(token string) bool

// TokenExtractor is a function that takes a request as input and returns
// either a token or an error.  An error should only be returned if an attempt
// to specify a token was found, but the information was somehow incorrectly
// formed.  In the case where a token is simply not present, this should not
// be treated as an error.  An empty string should be returned in that case.
type TokenExtractor func(ctx echo.Context) (string, error)

// Options is a struct for specifying configuration options for the middleware.
type Options struct {
	VerifyKey interface{}

	SignKey interface{}
	// The function that will return the Key to validate the JWT.
	// It can be either a shared secret or a public key.
	// Default value: nil
	// The name of the property in the request where the user information
	// from the JWT will be stored.
	// Default value: "user"
	UserProperty string
	// A function that extracts the token from the request
	// Default: FromAuthHeader (i.e., from Authorization header as bearer token)
	Extractor TokenExtractor
	// Debug flag turns on debugging output
	// Default: false
	Debug bool
	// When set, all requests with the OPTIONS method will use authentication
	// Default: false
	EnableAuthOnOptions bool
	// When set, the middelware verifies that tokens are signed with the specific signing algorithm
	// If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
	// Important to avoid security issues described here: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
	// Default: nil
	SigningMethod jwt.SigningMethod

	IsTokenInvoked IsTokenInvoked
}

type JwtAuth struct {
	Options Options
}

// New constructs a new Secure instance with supplied options.
func New(opts Options) *JwtAuth {

	if opts.SigningMethod == nil {
		opts.SigningMethod = jwt.SigningMethodHS256
	}

	if opts.UserProperty == "" {
		opts.UserProperty = "user"
	}

	if opts.Extractor == nil {
		opts.Extractor = FromAuthHeader
	}

	if opts.IsTokenInvoked == nil {
		opts.IsTokenInvoked = func(token string) bool {
			return false
		}
	}

	return &JwtAuth{
		Options: opts,
	}
}

func (m *JwtAuth) logf(format string, args ...interface{}) {
	if m.Options.Debug {
		log.Printf(format, args...)
	}
}

// Process is the middleware function.
func (self *JwtAuth) Verify(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {

		err := self.CheckJwt(c)

		if err == nil {
			return next(c)
		}

		return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
	}
}

func (self *JwtAuth) GenerateToken(claims Claims) (t *jwt.Token, tokenString string, err error) {
	t = jwt.New(self.Options.SigningMethod)
	t.Claims = claims
	tokenString, err = t.SignedString(self.Options.SignKey)
	t.Raw = tokenString
	return
}

// FromAuthHeader is a "TokenExtractor" that takes a give request and extracts
// the JWT token from the Authorization header.
func FromAuthHeader(ctx echo.Context) (string, error) {

	authHeader := ctx.Request().Header().Get(echo.HeaderAuthorization)
	if authHeader == "" {
		return "", nil // No error, just no token
	}

	// TODO: Make this a bit more robust, parsing-wise
	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", fmt.Errorf("Authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}

// FromParameter returns a function that extracts the token from the specified
// query string parameter
func FromParameter(param string) TokenExtractor {
	return func(ctx echo.Context) (string, error) {
		return ctx.QueryParam(param), nil
	}
}

// FromFirst returns a function that runs multiple token extractors and takes the
// first token it finds
func FromFirst(extractors ...TokenExtractor) TokenExtractor {
	return func(ctx echo.Context) (string, error) {
		for _, extract := range extractors {
			token, err := extract(ctx)
			if err != nil {
				return "", err
			}
			if token != "" {
				return token, nil
			}
		}
		return "", nil
	}
}

func (self *JwtAuth) getSignKey(_ *jwt.Token) (interface{}, error) {
	return self.Options.VerifyKey, nil
}

func (self *JwtAuth) CheckJwt(ctx echo.Context) error {

	req := ctx.Request()

	if !self.Options.EnableAuthOnOptions {
		if req.Method() == "OPTIONS" {
			return nil
		}
	}

	// Use the specified token extractor to extract a token from the request
	token, err := self.Options.Extractor(ctx)

	// If debugging is turned on, log the outcome
	if err != nil {
		self.logf("Error extracting JWT: %v", err)
	} else {
		self.logf("Token extracted: %s", token)
	}

	// If an error occurs, call the error handler and return an error
	if err != nil {
		//self.Options.ErrorHandler(ctx, err.Error())
		return fmt.Errorf("Error extracting token: %v", err)
	}

	// If the token is empty...
	if token == "" {
		//self.Options.ErrorHandler(ctx, errorMsg)
		return fmt.Errorf("Required authorization token not found")
	}

	// Now parse the token
	parsedToken, err := jwt.Parse(token, self.getSignKey)

	// Check if there was an error in parsing...
	if err != nil {
		self.logf("Error parsing token: %v", err)
		//self.Options.ErrorHandler(ctx, err.Error())
		return fmt.Errorf("Error parsing token: %v", err)
	}

	if self.Options.SigningMethod != nil && self.Options.SigningMethod.Alg() != parsedToken.Header["alg"] {
		message := fmt.Sprintf("Expected %s signing method but token specified %s",
			self.Options.SigningMethod.Alg(),
			parsedToken.Header["alg"])
		self.logf("Error validating token algorithm: %s", message)
		//self.Options.ErrorHandler(ctx, errors.New(message).Error())
		return fmt.Errorf("Error validating token algorithm: %s", message)
	}

	// Check if the parsed token is valid...
	if !parsedToken.Valid {
		self.logf("Token is invalid")
		//self.Options.ErrorHandler(ctx, "The token isn't valid")
		return fmt.Errorf("Token is invalid")
	}

	if self.Options.IsTokenInvoked(parsedToken.Raw) {
		self.logf("Token is invoked")
		//self.Options.ErrorHandler(ctx, "The token is invoked")
		return fmt.Errorf("Token is invoked")
	}

	self.logf("JWT: %v", parsedToken)

	// If we get here, everything worked and we can set the
	// user property in context.

	ctx.Set(self.Options.UserProperty, parsedToken.Claims)

	return nil
}
