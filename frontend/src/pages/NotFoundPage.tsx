import { Link } from "react-router-dom";

export function NotFoundPage() {
  return (
    <section className="mx-auto max-w-2xl">
      <h1 className="text-lg font-semibold text-slate-100">Page not found</h1>
      <p className="mt-2 text-sm text-slate-400">This page does not exist.</p>
      <Link to="/status" className="mt-4 inline-block text-sm text-sky-400 hover:underline">
        Go to system status
      </Link>
    </section>
  );
}
