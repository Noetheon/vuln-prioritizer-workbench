import { createFileRoute, redirect, useNavigate } from "@tanstack/react-router"
import { type FormEvent, useEffect, useState } from "react"
import { ApiError, LoginService, UtilsService } from "../api-client"
import { isLoggedIn, setAccessToken } from "../auth"
import { hasAuthenticatedSession } from "../lib/session-auth"

export const Route = createFileRoute("/login")({
  beforeLoad: async () => {
    if (isLoggedIn() || (await hasAuthenticatedSession())) {
      throw redirect({ search: {} as never, to: "/" })
    }
  },
  component: LoginPage,
})

function LoginPage() {
  const navigate = useNavigate()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [backendReady, setBackendReady] = useState(false)
  const [error, setError] = useState("")
  const [isSubmitting, setSubmitting] = useState(false)
  const errorId = "login-error"

  useEffect(() => {
    let isMounted = true

    async function loadStatus() {
      try {
        const health = await UtilsService.healthCheck()
        if (isMounted) {
          setBackendReady(health)
        }
      } catch {
        if (isMounted) {
          setBackendReady(false)
        }
      }
    }

    void loadStatus()
    return () => {
      isMounted = false
    }
  }, [])

  async function submitLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSubmitting(true)
    setError("")

    try {
      const token = await LoginService.loginAccessToken({
        bodyLoginLoginAccessToken: {
          username: email,
          password,
        },
      })
      setAccessToken(
        typeof token.access_token === "string" ? token.access_token : "",
      )
      await navigate({ search: {} as never, to: "/" })
    } catch (caught) {
      const message =
        caught instanceof ApiError && caught.status === 400
          ? "Email or password is incorrect."
          : "Sign-in service is unavailable."
      setError(message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="login-screen">
      <section className="login-panel" aria-labelledby="login-title">
        <div className="brand compact-brand">
          <div className="brand-mark" aria-hidden="true">
            VP
          </div>
          <div>
            <strong>Vuln Prioritizer</strong>
            <span>Workbench</span>
          </div>
        </div>

        <div className="login-copy">
          <span className="eyebrow">Risk Operations</span>
          <h1 id="login-title">Sign in</h1>
        </div>

        <form className="login-form" onSubmit={submitLogin}>
          <label>
            <span>Email</span>
            <input
              aria-describedby={error ? errorId : undefined}
              aria-invalid={error ? "true" : undefined}
              autoComplete="username"
              name="username"
              onChange={(event) => setEmail(event.target.value)}
              required
              type="email"
              value={email}
            />
          </label>
          <label>
            <span>Password</span>
            <input
              aria-describedby={error ? errorId : undefined}
              aria-invalid={error ? "true" : undefined}
              autoComplete="current-password"
              name="password"
              onChange={(event) => setPassword(event.target.value)}
              required
              type="password"
              value={password}
            />
          </label>
          {error ? (
            <p
              aria-live="polite"
              className="form-error"
              id={errorId}
              role="alert"
            >
              {error}
            </p>
          ) : null}
          <button
            className="primary-action"
            disabled={isSubmitting}
            type="submit"
          >
            {isSubmitting ? "Signing in" : "Sign in"}
          </button>
        </form>

        <div className="login-status" role="status">
          <span className={backendReady ? "status-dot" : "status-dot muted"} />
          <span>
            Workbench API ·{" "}
            {backendReady ? "data services ready" : "data services offline"}
          </span>
        </div>
      </section>
    </main>
  )
}
