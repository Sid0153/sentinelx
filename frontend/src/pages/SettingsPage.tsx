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
      <ChangePasswordForm />
      <TwoFactorPanel user={user} />
    </section>
  );
}
