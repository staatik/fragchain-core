import { FormEvent, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import { detailFromError } from "../api/client";
import { useAuth } from "../hooks/useAuth";

interface LocationState {
  from?: { pathname?: string };
}

function readNext(search: string, state: LocationState | null): string {
  if (state?.from?.pathname) return state.from.pathname;
  try {
    const params = new URLSearchParams(search);
    const next = params.get("next");
    if (next && next.startsWith("/")) return next;
  } catch {
    /* ignore */
  }
  return "/dashboard";
}

export function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();
  const state = (location.state ?? null) as LocationState | null;
  const target = readNext(location.search, state);

  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(username, password);
      navigate(target, { replace: true });
    } catch (err) {
      setError(detailFromError(err, "Login failed"));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="login-shell">
      <form className="login-card" onSubmit={onSubmit}>
        <div className="login-brand">
          FRAG<span className="accent">·CHAIN</span>
        </div>
        <div className="login-sub">Collaborative detection engineering</div>

        {error && <div className="login-error">{error}</div>}

        <div className="form-group">
          <label className="form-label" htmlFor="username">
            Username
          </label>
          <input
            id="username"
            className="input mono"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoFocus
          />
        </div>

        <div className="form-group">
          <label className="form-label" htmlFor="password">
            Password
          </label>
          <input
            id="password"
            className="input mono"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </div>

        <button
          type="submit"
          className="btn active"
          disabled={submitting}
          style={{ width: "100%" }}
        >
          {submitting ? "SIGNING IN…" : "SIGN IN"}
        </button>
      </form>
    </div>
  );
}
