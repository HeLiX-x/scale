bugs finding before deployment 

Confirmed — you found a real, legitimate dead-code path. This is actually a great interview talking point once you clean it up.

## What the Evidence Shows

Your live server (`main.go` + `authentication/routes/routes.go`) never touches `repositories.UserStore` or `handlers.UserHandler` at all. [main](main.go)

- `main.go` wires up: Postgres, Redis, `IPAllocator`, and Fiber routes via `routes.SetupRoutes`. [main](main.go)
- `routes.go` only registers `controllers.Register`, `controllers.Login`, `controllers.User`, `controllers.Logout` — all from `authentication/controllers`, which is the real, Postgres-backed, Fiber-based auth flow. [authentication](authentication/routes/routes.go)
- `handlers/user_handler.go` and `repositories/user_store.go` use a **completely different web framework** (`gin`, not `fiber`) and are never imported by `main.go` or `routes.go`. [handlers](handlers/user_handler.go)

So this in-memory map isn't just a bad practice sitting next to Postgres — it's **fully orphaned code** from what looks like an earlier prototype (before you switched from Gin to Fiber and wired in real Postgres auth). Nothing in the running binary ever calls `NewInMemoryUserStore()`.

## Why This Matters for Interviews

This is actually a **stronger story** than "I have a bug." The correct framing is:

> "During cleanup for this session I actually verified something I'd flagged earlier — the `repositories/user_store.go` in-memory map and its Gin-based handler in `handlers/user_handler.go` are dead code. They belong to an earlier iteration of the project that used Gin instead of Fiber, before I migrated to Postgres-backed auth. They're never wired into `main.go` or the route table, so removing them doesn't change runtime behavior — it's pure hygiene."

That's a **much better answer** than admitting a live bug — it shows you can trace call graphs and distinguish "dead prototype code" from "active bug," which is a real signal of engineering maturity.

## What to Actually Delete

| File | Why it's safe to remove |
|---|---|
| `repositories/user_store.go` | `InMemoryUserStore`, never instantiated anywhere in the live path  [repositories](repositories/user_store.go) |
| `handlers/user_handler.go` | Depends on `gin.Context`, never imported by `main.go` or routes  [handlers](handlers/user_handler.go) |

Also worth checking: whether `gin-gonic/gin` and `gosimple/slug` are still needed in `go.mod` after removing this — if not, `go mod tidy` would clean those up too.

## What NOT to Touch

Keep `authentication/controllers/authcontroller.go`, `database/database.go`, and `models/user.go` — those are the real, Postgres+GORM-backed user auth path actually running in production. [main](main.go)


-------------------------------------------------------------------------------------------------------------------------------------------------

Access/Refresh feature unused : 



Short answer: **no — not really.** Your project has the *code* for access/refresh tokens sitting in `internal/util/tokenutil.go` and `claims.go`, but that code is never called anywhere in your live auth flow. This is the same pattern as the `UserStore` dead code you found earlier.

## What Actually Exists (Unused)

`internal/util/tokenutil.go` defines two functions that look like a proper access/refresh token system: [internal](internal/util/tokenutil.go)

- `CreateAccessToken(user, secret, expiry)` — builds a JWT with `JwtCustomClaims{Name, ID, RegisteredClaims}` and a configurable expiry. [internal](internal/util/tokenutil.go)
- `CreateRefreshToken(user, secret, expiry)` — builds a separate JWT with `JwtCustomRefreshClaims{ID, RegisteredClaims}`, meant to have a longer life and a different secret. [internal](internal/util/tokenutil.go)

`claims.go` even has a `Config` struct ready for this — `AccessTokenExpiryHour`, `RefreshTokenExpiryHour`, `AccessTokenSecret`, `RefreshTokenSecret` — which is exactly the shape you'd need to wire up dual-secret access/refresh rotation.

**None of this is called anywhere.** I traced every usage: `authcontroller.go`, `routes.go`, `main.go` — nowhere does `CreateAccessToken` or `CreateRefreshToken` get invoked.

## What's Actually Running

Your real, live login flow in `authcontroller.go` does something much simpler:

- `Login()` builds a **single JWT** manually with `jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": ..., "exp": 24 hours})`.
- That one token is set as an `HttpOnly` cookie **and** also returned in the JSON response body.
- There is **no refresh token, no rotation, no separate short/long-lived pair** — just one 24-hour token that acts as both access and "session."
- What actually validates it on protected routes is `JwtAuthMiddleware`, which calls `util.IsAuthorized` and `util.ExtractIDFromToken` — reused from the same `internal/util` package, but only the `IsAuthorized`/`ExtractIDFromToken` functions, not the token-creation ones. [internal](internal/util/tokenutil.go)

## The Honest Story

This is a great pattern to notice and say out loud, because it shows you can read your own codebase critically:

> "I actually designed a proper access/refresh token system with separate claim types and configurable expiries in `internal/util`, but I never wired it into the actual login handler — `Login()` still issues a single long-lived JWT manually. So right now there's no refresh flow: when the 24-hour token expires, the user just has to log in again. The scaffolding for refresh tokens exists, but the rotation logic and a `/api/refresh` endpoint were never built."

## What a Real Refresh Flow Would Need (If Asked "How Would You Fix This?")

- A `/api/refresh` route that accepts the refresh token and issues a new access token.
- Two different secrets (`AccessTokenSecret` vs `RefreshTokenSecret`) as your `Config` struct already anticipates.
- Refresh token storage/invalidation (e.g., a Redis key per refresh token, or a `token_version` field on the user row) so logout can actually revoke it — right now `Logout()` just clears the cookie client-side, it doesn't invalidate the JWT server-side, so a stolen token remains valid until it naturally expires.

That last point — **your `Logout()` doesn't actually invalidate anything server-side** — is worth mentioning proactively, since stateless JWTs can't be revoked without an extra layer like a blocklist, and interviewers love probing "how do you log a user out with JWTs?"
