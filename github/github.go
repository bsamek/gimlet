package github

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/evergreen-ci/evergreen"
	"github.com/evergreen-ci/evergreen/thirdparty"
	"github.com/evergreen-ci/gimlet"
	"github.com/mongodb/grip"
	"github.com/pkg/errors"
)

// GithubAuthManager implements the UserManager with GitHub authentication using Oauth authentication.
// The process starts off with a redirect GET request to GitHub sent with the application's ClientID,
// the CallbackURI of the application where Github should redirect the user to after authenticating with username/password,
// the scope (the email and organization information of the user the application uses to authorize the user,
// and an unguessable State string. The state string is concatenation of a timestamp and a hash of the timestamp
// and the Salt field in userService.
// After authenticating the User, GitHub redirects the user back to the CallbackURI given with a code parameter
// and the unguessable State string. The application checks that the State strings are the same by reproducing
// the state string using the Salt and the timestamp that is in plain-text before the hash and checking to make sure
// that they are the same.
// The application sends the code back in a POST with the ClientID and ClientSecret and receives a response that has the
// accessToken used to get the user's information. The application stores the accessToken in a session cookie.
// Whenever GetUserByToken is called, the application sends the token to GitHub, gets the user's login username and organization
// and ensures that the user is either in an Authorized organization or an Authorized user.

type userService struct {
	opts Opts
}

type Opts struct {
	AuthorizedOrganization string
	AuthorizedUsers        []string
	ClientID               string
	ClientSecret           string
	Salt                   string

	GetUser       gimlet.GetUserByID
	GetCreateUser gimlet.GetOrCreateUser
	SetToken      gimlet.SetLoginToken
}

// NewUserService initializes a userService with a Salt as randomly generated string used in Github
// authentication
func NewUserService(g *evergreen.GithubAuthConfig, opts Opts) (gimlet.UserManager, error) {
	if opts.AuthorizedOrganization == "" || len(opts.AuthorizedUsers) == 0 {
		return nil, errors.New("authorized organization or users must be specified")
	}
	if opts.ClientID == "" {
		return nil, errors.New("must specify a client id")
	}
	if opts.ClientSecret == "" {
		return nil, errors.New("must specify a client secret")
	}
	if opts.Salt == "" {
		return nil, errors.New("must specify a salt")
	}
	if opts.GetUser == nil {
		return nil, errors.New("must specify GetUser function")
	}
	if opts.GetCreateUser == nil {
		return nil, errors.New("must specify GetCreateUser function")
	}
	if opts.SetToken == nil {
		return nil, errors.New("must specify SetToken function")
	}
	return &userService{opts}, nil
}

// GetUserByToken sends the token to Github and gets back a user and optionally an organization.
// If there are Authorized Users, it checks the authorized usernames against the GitHub user's login
// If there is no match and there is an organization it checks the user's organizations against
// the UserManager's Authorized organization string.
func (u *userService) GetUserByToken(ctx context.Context, token string) (gimlet.User, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	user, isMember, err := thirdparty.GetGithubTokenUser(ctx, token, u.opts.AuthorizedOrganization)
	if err != nil {
		return nil, err
	}
	if user != nil {
		if !isMember {
			if u.opts.AuthorizedUsers != nil {
				for _, u := range u.opts.AuthorizedUsers {
					if u == user.Username() {
						return user, nil
					}
				}
			}

		} else {
			return user, nil
		}
	}

	return nil, errors.New("No authorized user or organization given")
}

// CreateUserToken is not implemented in userService
func (u *userService) CreateUserToken(string, string) (string, error) {
	return "", errors.New("userService does not create tokens via username/password")
}

// GetLoginHandler returns the function that starts oauth by redirecting the user to authenticate with Github
func (u *userService) GetLoginHandler(callbackUri string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		githubScope := "user:email, read:org"
		githubUrl := "https://github.com/login/oauth/authorize"
		timestamp := time.Now().String()
		// create a combination of the current time and the config's salt to hash as the unguessable string
		githubState := fmt.Sprintf("%v%x", timestamp, md5.Sum([]byte(timestamp+u.opts.Salt)))
		parameters := url.Values{}
		parameters.Set("client_id", u.opts.ClientID)
		parameters.Set("redirect_uri", fmt.Sprintf("%v/login/redirect/callback?%v", callbackUri, r.URL.RawQuery))
		parameters.Set("scope", githubScope)
		parameters.Set("state", githubState)
		http.Redirect(w, r, fmt.Sprintf("%v?%v", githubUrl, parameters.Encode()), http.StatusFound)
	}
}

// GetLoginCallbackHandler returns the function that is called when GitHub redirects the user back to Evergreen.
func (u *userService) GetLoginCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.FormValue("code")
		if code == "" {
			grip.Error("Error getting code from github for authentication")
			return
		}
		githubState := r.FormValue("state")
		if githubState == "" {
			grip.Error("Error getting state from github for authentication")
			return
		}
		// if there is an internal redirect page, redirect the user back to that page
		// otherwise redirect the user back to the home page
		redirect := r.FormValue("redirect")
		if redirect == "" {
			redirect = "/"
		}
		// create the state from the timestamp and Salt and check against the one GitHub sent back
		timestamp := githubState[:len(time.Now().String())]
		state := fmt.Sprintf("%v%x", timestamp, md5.Sum([]byte(timestamp+u.opts.Salt)))

		// if the state doesn't match, log the error and redirect back to the login page
		if githubState != state {
			grip.Errorf("Error unmatching states when authenticating with GitHub: ours: %vb, theirs %v",
				state, githubState)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		githubResponse, err := thirdparty.GithubAuthenticate(ctx, code, u.opts.ClientID, u.opts.ClientSecret)
		if err != nil {
			grip.Errorf("Error sending code and authentication info to Github: %+v", err)
			return
		}
		u.opts.SetToken(githubResponse.AccessToken, w)
		http.Redirect(w, r, redirect, http.StatusFound)
	}
}

func (u *userService) IsRedirect() bool                           { return true }
func (u *userService) GetUserByID(id string) (gimlet.User, error) { return u.opts.GetUser(id) }
func (u *userService) GetOrCreateUser(user gimlet.User) (gimlet.User, error) {
	return u.opts.GetCreateUser(user)
}
func (u *userService) ClearUser(user gimlet.User, all bool) error {
	return errors.New("Github Authentication does not support Clear User")
}
