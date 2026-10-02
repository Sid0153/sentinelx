import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { currentUser, guestLogin, login, logout, restoreSession, type SecondFactor } from "../services/auth";
import { onSessionExpired } from "../services/http";
import type { Role, User } from "../types/api";

type AuthState =
  | { status: "loading" }
  | { status: "unauthenticated"; reason?: "expired" | "signed_out" | "password_changed" }
  | { status: "authenticated"; user: User };

interface AuthContextValue {
  state: AuthState;
  signIn: (email: string, password: string, second?: SecondFactor) => Promise<void>;
  /** A public demo's read-only guest (only when the server offers it). */
  signInAsGuest: () => Promise<void>;
  signOut: (reason?: "signed_out" | "password_changed") => Promise<void>;
  /** Reloads the signed-in user (after turning two-factor sign-in on or off). */
  reloadUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const RANK: Record<Role, number> = { VIEWER: 1, ANALYST: 2, ADMIN: 3 };

/** UI convenience only: the API enforces every role check itself (ADR-0007). */
export function hasRole(user: User, minimum: Role): boolean {
  return RANK[user.role] >= RANK[minimum];
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    restoreSession()
      .then((user) => {
        if (!cancelled) setState({ status: "authenticated", user });
      })
      .catch(() => {
        if (!cancelled) setState({ status: "unauthenticated" });
      });
    onSessionExpired(() => setState({ status: "unauthenticated", reason: "expired" }));
    return () => {
      cancelled = true;
      onSessionExpired(null);
    };
  }, []);

  const signIn = useCallback(async (email: string, password: string, second?: SecondFactor) => {
    const user = await login(email, password, second);
    setState({ status: "authenticated", user });
  }, []);

  const signInAsGuest = useCallback(async () => {
    const user = await guestLogin();
    setState({ status: "authenticated", user });
  }, []);

  const reloadUser = useCallback(async () => {
    const user = await currentUser();
    setState({ status: "authenticated", user });
  }, []);

  const signOut = useCallback(async (reason: "signed_out" | "password_changed" = "signed_out") => {
    try {
      await logout();
    } catch {
      // Even if the server cannot be reached, this browser forgets the session.
    }
    setState({ status: "unauthenticated", reason });
  }, []);

  const value = useMemo(
    () => ({ state, signIn, signInAsGuest, signOut, reloadUser }),
    [state, signIn, signInAsGuest, signOut, reloadUser],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === null) throw new Error("useAuth must be used inside <AuthProvider>");
  return context;
}

/** The signed-in user. Only for components rendered inside <RequireAuth>. */
export function useCurrentUser(): User {
  const { state } = useAuth();
  if (state.status !== "authenticated") throw new Error("useCurrentUser outside <RequireAuth>");
  return state.user;
}
