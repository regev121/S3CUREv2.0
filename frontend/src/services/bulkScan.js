import { useEffect, useRef, useState } from "react";
import api from "./api";

const active = (job) => ["queued", "running"].includes(job.status);

export function useBulkScan() {
  const request = useRef(null);
  const [busy, setBusy] = useState(false);
  const [job, setJob] = useState(null);

  useEffect(() => () => request.current?.abort(), []);

  const run = async (path) => {
    if (request.current) return null;
    const controller = new AbortController();
    request.current = controller;
    const { signal } = controller;
    setJob(null);
    setBusy(true);
    try {
      let { data } = await api.post(path, null, { signal });
      setJob(data);
      while (active(data)) {
        await new Promise((resolve) => setTimeout(resolve, 1200));
        if (signal.aborted) return null;
        ({ data } = await api.get("/api/scan/jobs/" + encodeURIComponent(data.job_id), { signal }));
        setJob(data);
      }
      return data;
    } catch (error) {
      if (!signal.aborted) throw error;
      return null;
    } finally {
      request.current = null;
      if (!signal.aborted) setBusy(false);
    }
  };

  const progress = job?.status === "running" && job.total > 0
    ? `${job.scanned + job.failed} / ${job.total} processed`
    : "Starting scan…";
  return { run, busy, progress };
}
