import { useCurrentUser } from "../auth/AuthContext";
import { ChangePasswordForm, TwoFactorPanel } from "../components/account";
import { formatUtc, PageHeader } from "../components/ui";

export function SettingsPage() {
  const user = useCurrentUser();
  return (
    <section>
      <PageHeader title="Account" />
      <dl className="mb-4 grid max-w-md grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-slate-400">Email</dt>
        <dd className="text-slate-100">{user.email}</dd>
        <dt className="text-slate-400">Role</dt>
        <dd className="text-slate-100">{user.role}</dd>
        <dt className="text-slate-400">Last sign-in</dt>
        <dd className="font-mono text-xs text-slate-300">{formatUtc(user.last_login_at)}</dd>
      </dl>
      {user.is_guest ? (
        <p className="max-w-xl text-sm text-slate-300">
          This is the public demo&apos;s shared guest account. It can look at everything and change
          nothing, and its sign-in settings are fixed, so no visitor can lock the others out.
        </p>
      ) : (
        <>
          <ChangePasswordForm />
          <TwoFactorPanel user={user} />
        </>
      )}
    </section>
  );
}
