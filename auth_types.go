package gimlet

import (
	"net/http"
)

// PutUserGetToken is a function provided by the client to cache users. It generates, saves, and
// returns a new token. Updating the user's TTL should happen in this function.
type PutUserGetToken func(User) (string, error)

// GetUserByToken is a function provided by the client to retrieve cached users by token.
// It returns an error if and only if there was an error retrieving the user from the cache.
// It returns (<user>, true, nil) if the user is present in the cache and is valid.
// It returns (<user>, false, nil) if the user is present in the cache but has expired.
// It returns (nil, false, nil) if the user is not present in the cache.
type GetUserByToken func(string) (User, bool, error)

// ClearUserToken is a function provided by the client to remove users' tokens from
// cache. Passing true will ignore the user passed and clear all users.
type ClearUserToken func(User, bool) error

// GetUserByID is a function provided by the client to get a user from persistent storage.
type GetUserByID func(string) (User, error)

// GetOrCreateUser is a function provided by the client to get a user from
// persistent storage, or if the user does not exist, to create and save it.
type GetOrCreateUser func(User) (User, error)

// SetLoginToken is a function provided by the client to set the login token in the session cookie
// for authentication.
type SetLoginToken func(token string, w http.ResponseWriter)
