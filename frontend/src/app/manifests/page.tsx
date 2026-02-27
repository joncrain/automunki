"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { api, type ManifestRead } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { FileText, ArrowRight } from "lucide-react";

export default function ManifestsPage() {
  const { data: manifests, isLoading } = useQuery({
    queryKey: ["manifests"],
    queryFn: () => api.get<ManifestRead[]>("/manifests"),
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
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Manifests</h1>
      </div>

      <div className="grid gap-4">
        {manifests?.map((manifest) => (
          <Card key={manifest.id} className="border-l-4 border-l-primary/40">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <FileText className="h-5 w-5 text-primary" />
                  <span>{manifest.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  {manifest.catalog_names.map((c) => (
                    <Badge key={c} variant="secondary">
                      {c}
                    </Badge>
                  ))}
                  <Button variant="outline" size="sm" asChild>
                    <Link href={`/manifests/${manifest.id}`}>
                      Edit
                      <ArrowRight className="ml-1 h-4 w-4" />
                    </Link>
                  </Button>
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {manifest.managed_installs.length > 0 && (
                <div>
                  <h4 className="mb-2 text-sm font-medium text-muted-foreground">
                    Managed Installs
                  </h4>
                  <div className="flex flex-wrap gap-1">
                    {manifest.managed_installs.map((item) => (
                      <Badge key={item} variant="outline">
                        {item}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {manifest.managed_uninstalls.length > 0 && (
                <div>
                  <h4 className="mb-2 text-sm font-medium text-muted-foreground">
                    Managed Uninstalls
                  </h4>
                  <div className="flex flex-wrap gap-1">
                    {manifest.managed_uninstalls.map((item) => (
                      <Badge key={item} variant="destructive">
                        {item}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {manifest.optional_installs.length > 0 && (
                <div>
                  <h4 className="mb-2 text-sm font-medium text-muted-foreground">
                    Optional Installs
                  </h4>
                  <div className="flex flex-wrap gap-1">
                    {manifest.optional_installs.map((item) => (
                      <Badge key={item} variant="outline">
                        {item}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {manifest.included_manifest_names.length > 0 && (
                <>
                  <Separator />
                  <div>
                    <h4 className="mb-2 text-sm font-medium text-muted-foreground">
                      Included Manifests
                    </h4>
                    <div className="flex flex-wrap gap-1">
                      {manifest.included_manifest_names.map((name) => (
                        <Badge key={name} variant="secondary">
                          {name}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </>
              )}

              <p
                suppressHydrationWarning
                className="text-xs text-muted-foreground"
              >
                Updated {formatDateTime(manifest.updated_at)}
              </p>
            </CardContent>
          </Card>
        ))}

        {!manifests?.length && (
          <p className="text-muted-foreground">
            No manifests found. Import your Munki repo to get started.
          </p>
        )}
      </div>
    </div>
  );
}
