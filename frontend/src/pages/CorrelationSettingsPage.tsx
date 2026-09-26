import { useCallback, useEffect, useState } from "react";

import { Button, ErrorMessage, Field, PageHeader, inputClass } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { ApiError } from "../services/http";
import { getCorrelationSettings, updateCorrelationSettings } from "../services/incidents";

export function CorrelationSettingsPage() {
  const load = useCallback((signal: AbortSignal) => getCorrelationSettings(signal), []);
  const { data, error, reload } = useApi(load);
  const [correlation, setCorrelation] = useState("");
  const [sequence, setSequence] = useState("");
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (data) {
      setCorrelation(String(data.correlation_window_minutes));
      setSequence(String(data.sequence_window_minutes));
    }
  }, [data]);

  async function save() {
    setSaveError(null);
    setSaved(false);
    try {
      await updateCorrelationSettings({
        correlation_window_minutes: Number(correlation),
        sequence_window_minutes: Number(sequence),
      });
      setSaved(true);
      reload();
    } catch (caught) {
      setSaveError(caught instanceof ApiError ? caught.message : "The settings could not be saved.");
    }
  }

  return (
    <section className="max-w-xl">
      <PageHeader
        title="Correlation"
        description="How far apart in time alerts may be and still be grouped into one incident. Changes apply to the next detection run and are audited."
      />
      {error ? (
        <ErrorMessage>{error.message}</ErrorMessage>
      ) : !data ? (
        <p className="text-sm text-slate-400">Loading settings…</p>
      ) : (
        <form
          aria-label="Correlation settings"
          className="space-y-4 rounded-lg border border-slate-800 bg-slate-900 p-4"
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <Field
            label="Correlation window (minutes)"
            hint="15 to 1,440. An alert joins an incident whose activity is at most this far away."
          >
            <input
              type="number"
              min={15}
              max={1440}
              value={correlation}
              onChange={(e) => setCorrelation(e.target.value)}
              className={inputClass}
            />
          </Field>
          <Field
            label="Sequence window (minutes)"
            hint="5 to 240, not longer than the correlation window. Used when an alert shares only the host but is a new kind of finding."
          >
            <input
              type="number"
              min={5}
              max={240}
              value={sequence}
              onChange={(e) => setSequence(e.target.value)}
              className={inputClass}
            />
          </Field>
          {saveError && <ErrorMessage>{saveError}</ErrorMessage>}
          {saved && <p className="text-sm text-emerald-300">Saved.</p>}
          <Button type="submit">Save</Button>
        </form>
      )}
    </section>
  );
}
