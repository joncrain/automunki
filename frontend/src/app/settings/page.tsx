"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Settings</h1>

      <Card>
        <CardHeader>
          <CardTitle>GitHub Integration</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2">
            <Label htmlFor="github-repo">Repository</Label>
            <Input
              id="github-repo"
              placeholder="owner/repo"
              disabled
            />
            <p className="text-sm text-muted-foreground">
              Configured via GITHUB_REPO environment variable
            </p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>AWS / S3 Configuration</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2">
            <Label htmlFor="s3-bucket">S3 Bucket</Label>
            <Input id="s3-bucket" placeholder="my-munki-bucket" disabled />
            <p className="text-sm text-muted-foreground">
              Configured via AWS_S3_BUCKET environment variable
            </p>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="cf-dist">CloudFront Distribution ID</Label>
            <Input id="cf-dist" placeholder="E1234567890" disabled />
            <p className="text-sm text-muted-foreground">
              Configured via CLOUDFRONT_DISTRIBUTION_ID environment variable
            </p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Notifications</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2">
            <Label htmlFor="slack-webhook">Slack Webhook URL</Label>
            <Input
              id="slack-webhook"
              type="password"
              placeholder="https://hooks.slack.com/..."
              disabled
            />
            <p className="text-sm text-muted-foreground">
              Configured via SLACK_WEBHOOK_URL environment variable
            </p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>About</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-2">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Version</span>
              <span>0.1.0</span>
            </div>
            <Separator />
            <div className="flex justify-between">
              <span className="text-muted-foreground">Backend</span>
              <span>FastAPI + Python 3.12</span>
            </div>
            <Separator />
            <div className="flex justify-between">
              <span className="text-muted-foreground">Frontend</span>
              <span>Next.js + React</span>
            </div>
            <Separator />
            <div className="flex justify-between">
              <span className="text-muted-foreground">Database</span>
              <span>PostgreSQL 16</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
