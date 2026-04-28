import { createFileRoute, redirect, useNavigate } from "@tanstack/react-router"
import { type FormEvent, useEffect, useState } from "react"
import { isLoggedIn, setAccessToken } from "../auth"
import {
  ApiError,
  LoginService,
  UtilsService,
  WorkbenchService,
  type WorkbenchStatus,
} from "../client"

export const Route = createFileRoute("/login")({
  beforeLoad: () => {
    if (isLoggedIn()) {
      throw redirect({ to: "/" })
    }
  },
  component: LoginPage,
})

function LoginPage() {
  const navigate = useNavigate()
  const [email, setEmail] = useState("admin@example.com")
  const [password, setPassword] = useState("changethis")
  const [backendReady, setBackendReady] = useState(false)
  const [status, setStatus] = useState<WorkbenchStatus | null>(null)
  const [error, setError] = useState("")
  const [isSubmitting, setSubmitting] = useState(false)

  useEffect(() => {
    let isMounted = true

    async function loadStatus() {
      try {
        const [health, workbenchStatus] = await Promise.all([
          UtilsService.healthCheck(),
          WorkbenchService.templateWorkbenchStatus(),
        ])
        if (isMounted) {
          setBackendReady(health)
          setStatus(workbenchStatus)
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
        formData: {
          username: email,
          password,
        },
      })
      setAccessToken(token.access_token)
      await navigate({ to: "/" })
    } catch (caught) {
      const message =
        caught instanceof ApiError && caught.status === 400
          ? "Email or password is incorrect."
          : "Backend login is unavailable."
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
          <span className="eyebrow">FastAPI Template</span>
          <h1 id="login-title">Sign in</h1>
        </div>

        <form className="login-form" onSubmit={submitLogin}>
          <label>
            <span>Email</span>
            <input
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
              autoComplete="current-password"
              name="password"
              onChange={(event) => setPassword(event.target.value)}
              required
              type="password"
              value={password}
            />
          </label>
          {error ? <p className="form-error">{error}</p> : null}
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
            {status?.app ?? "Vuln Prioritizer Workbench"} ·{" "}
            {backendReady ? "backend ready" : "backend offline"}
          </span>
        </div>
      </section>
    </main>
  )
}
