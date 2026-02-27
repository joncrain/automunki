"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { api, type RunResultRead } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CheckCircle, XCircle } from "lucide-react";

export default function ApprovalsPage() {
  const queryClient = useQueryClient();

  const { data: approvals, isLoading } = useQuery({
    queryKey: ["pending-approvals"],
    queryFn: () => api.get<RunResultRead[]>("/autopkg/approvals"),
  });

  const approveMutation = useMutation({
    mutationFn: ({
      id,
      approved,
    }: {
      id: string;
      approved: boolean;
    }) => api.post(`/autopkg/results/${id}/approve`, { approved }),
    onSuccess: (_, variables) => {
      toast.success(
        variables.approved ? "Item approved" : "Item rejected"
      );
      queryClient.invalidateQueries({ queryKey: ["pending-approvals"] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        Loading...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Approval Queue</h1>

      {approvals?.length ? (
        <div className="space-y-4">
          {approvals.map((item) => (
            <Card
              key={item.id}
              className="border-l-4 border-l-amber-500/40"
            >
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span>{item.recipe_name}</span>
                    <Badge
                      variant={
                        item.status === "imported"
                          ? "default"
                          : item.status === "trust_failed"
                            ? "destructive"
                            : "secondary"
                      }
                    >
                      {item.status}
                    </Badge>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="default"
                      aria-label={`Approve ${item.recipe_name}`}
                      onClick={() =>
                        approveMutation.mutate({
                          id: item.id,
                          approved: true,
                        })
                      }
                      disabled={approveMutation.isPending}
                    >
                      <CheckCircle className="mr-1 h-4 w-4" />
                      Approve
                    </Button>
                    <Button
                      size="sm"
                      variant="destructive"
                      aria-label={`Reject ${item.recipe_name}`}
                      onClick={() =>
                        approveMutation.mutate({
                          id: item.id,
                          approved: false,
                        })
                      }
                      disabled={approveMutation.isPending}
                    >
                      <XCircle className="mr-1 h-4 w-4" />
                      Reject
                    </Button>
                  </div>
                </CardTitle>
              </CardHeader>
              <CardContent className="grid gap-2 md:grid-cols-3">
                {item.imported_version && (
                  <div>
                    <span className="text-sm text-muted-foreground">
                      Version
                    </span>
                    <p className="font-mono">{item.imported_version}</p>
                  </div>
                )}
                {item.imported_catalogs && (
                  <div>
                    <span className="text-sm text-muted-foreground">
                      Catalogs
                    </span>
                    <div className="mt-1 flex gap-1">
                      {item.imported_catalogs.map((c) => (
                        <Badge key={c} variant="secondary">
                          {c}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                <div>
                  <span className="text-sm text-muted-foreground">Date</span>
                  <p suppressHydrationWarning>
                    {formatDateTime(item.created_at)}
                  </p>
                </div>
                {item.error_message && (
                  <div className="col-span-full">
                    <span className="text-sm text-muted-foreground">
                      Error
                    </span>
                    <pre className="mt-1 overflow-auto rounded-md bg-muted p-2 text-sm">
                      {item.error_message}
                    </pre>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <Card>
          <CardContent className="flex items-center justify-center p-12">
            <div className="text-center">
              <CheckCircle
                className="mx-auto h-12 w-12 text-emerald-500/50"
                aria-hidden="true"
              />
              <h3 className="mt-4 text-lg font-medium">All caught up!</h3>
              <p className="text-sm text-muted-foreground">
                No items pending approval
              </p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
