"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { api, type SyncJobRead } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { RefreshCw } from "lucide-react";

const statusVariant = (status: string) => {
  switch (status) {
    case "completed":
      return "default" as const;
    case "failed":
      return "destructive" as const;
    case "running":
      return "secondary" as const;
    default:
      return "outline" as const;
  }
};

export default function SyncPage() {
  const queryClient = useQueryClient();

  const { data: status } = useQuery({
    queryKey: ["sync-status"],
    queryFn: () => api.get<Record<string, unknown>>("/sync/status"),
  });

  const { data: history } = useQuery({
    queryKey: ["sync-history"],
    queryFn: () =>
      api.get<{ items: SyncJobRead[]; total: number }>("/sync/history"),
  });

  const syncMutation = useMutation({
    mutationFn: () => api.post("/sync/compile"),
    onSuccess: () => {
      toast.success("Sync triggered");
      queryClient.invalidateQueries({ queryKey: ["sync-status"] });
      queryClient.invalidateQueries({ queryKey: ["sync-history"] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Repo Sync</h1>
        <Button
          onClick={() => syncMutation.mutate()}
          disabled={syncMutation.isPending}
        >
          <RefreshCw className="mr-2 h-4 w-4" />
          {syncMutation.isPending ? "Triggering..." : "Trigger Sync"}
        </Button>
      </div>

      <Card className="border-l-4 border-l-blue-500/40">
        <CardHeader>
          <CardTitle>Current Status</CardTitle>
        </CardHeader>
        <CardContent>
          {status && status.status !== "no_syncs" ? (
            <div className="grid gap-4 md:grid-cols-3">
              <div>
                <span className="text-sm text-muted-foreground">Status</span>
                <div className="mt-1">
                  <Badge variant={statusVariant(status.status as string)}>
                    {status.status as string}
                  </Badge>
                </div>
              </div>
              <div>
                <span className="text-sm text-muted-foreground">
                  Triggered By
                </span>
                <p className="mt-1">{(status.triggered_by as string) || "\u2014"}</p>
              </div>
              <div>
                <span className="text-sm text-muted-foreground">
                  Files Synced
                </span>
                <p
                  className="mt-1"
                  style={{ fontVariantNumeric: "tabular-nums" }}
                >
                  {(status.files_synced as number) ?? "\u2014"}
                </p>
              </div>
            </div>
          ) : (
            <p className="text-muted-foreground">No syncs have been run yet</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Sync History</CardTitle>
        </CardHeader>
        <CardContent>
          {history?.items?.length ? (
            <div className="space-y-2">
              {history.items.map((job) => (
                <div
                  key={job.id}
                  className="flex items-center justify-between rounded-md border p-3"
                >
                  <div className="flex items-center gap-3">
                    <Badge variant={statusVariant(job.status)}>
                      {job.status}
                    </Badge>
                    <span className="text-sm">
                      {job.triggered_by || "system"}
                    </span>
                    {job.files_synced != null && (
                      <span
                        className="text-sm text-muted-foreground"
                        style={{ fontVariantNumeric: "tabular-nums" }}
                      >
                        {job.files_synced} files
                      </span>
                    )}
                  </div>
                  <span
                    suppressHydrationWarning
                    className="text-sm text-muted-foreground"
                  >
                    {formatDateTime(job.created_at)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-muted-foreground">No sync history</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
