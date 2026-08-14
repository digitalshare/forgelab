import { getReadiness, type ReadinessReport } from "@/lib/api";

/**
 * Placeholder shell. The real surfaces land with their work orders:
 * challenge intake (WO-015), the three-lane arena (WO-019), and the
 * result review workspace (WO-049).
 */
export default async function Home() {
  let readiness: ReadinessReport | null = null;
  let error: string | null = null;

  try {
    readiness = await getReadiness();
  } catch {
    error = "API unreachable — start it with `make api`.";
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-3xl flex-col justify-center gap-8 p-8">
      <div>
        <h1 className="text-4xl font-semibold tracking-tight">ForgeLab</h1>
        <p className="mt-2 text-neutral-500">
          Three AI agents. One challenge. Isolated sandboxes. One winning pull request.
        </p>
      </div>

      <section className="rounded-lg border border-neutral-200 p-5 dark:border-neutral-800">
        <h2 className="text-sm font-medium uppercase tracking-wide text-neutral-500">
          Backend status
        </h2>

        {error ? (
          <p className="mt-3 text-sm text-amber-600">{error}</p>
        ) : (
          <ul className="mt-3 space-y-1.5">
            {Object.entries(readiness?.checks ?? {}).map(([name, status]) => (
              <li key={name} className="flex items-center justify-between text-sm">
                <span className="font-mono text-neutral-600 dark:text-neutral-400">{name}</span>
                <span className={status === "ok" ? "text-emerald-600" : "text-red-600"}>
                  {status}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </main>
  );
}
