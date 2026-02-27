"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, GitFork, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
	DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { type AutoPkgRepoRead, api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";

export default function ReposPage() {
	const queryClient = useQueryClient();

	const { data: repos, isLoading } = useQuery({
		queryKey: ["autopkg-repos"],
		queryFn: () => api.get<AutoPkgRepoRead[]>("/autopkg/repos"),
	});

	const deleteMutation = useMutation({
		mutationFn: (id: string) => api.delete(`/autopkg/repos/${id}`),
		onSuccess: () => {
			toast.success("Repo removed");
			queryClient.invalidateQueries({ queryKey: ["autopkg-repos"] });
		},
		onError: (err: Error) => toast.error(err.message),
	});

	return (
		<div className="space-y-6">
			<div className="flex items-center justify-between">
				<div>
					<h1 className="text-3xl font-bold">AutoPkg Repos</h1>
					<p className="mt-1 text-muted-foreground">
						Manage the recipe repositories used during AutoPkg runs. These map
						to entries in <code className="text-xs">repo_list.txt</code>.
					</p>
				</div>
				<AddRepoDialog />
			</div>

			{isLoading ? (
				<div className="py-12 text-center text-muted-foreground">
					Loading...
				</div>
			) : (repos ?? []).length === 0 ? (
				<Card>
					<CardContent className="py-12 text-center text-muted-foreground">
						No repos configured yet. Click &ldquo;Add Repo&rdquo; to get
						started.
					</CardContent>
				</Card>
			) : (
				<div className="grid gap-3 md:grid-cols-2">
					{(repos ?? []).map((repo) => (
						<Card key={repo.id} className="border-l-4 border-l-violet-500/40">
							<CardHeader className="pb-2">
								<CardTitle className="flex items-center justify-between text-sm">
									<div className="flex items-center gap-2 truncate">
										<GitFork
											className="h-4 w-4 shrink-0 text-violet-500"
											aria-hidden="true"
										/>
										<span className="truncate font-medium">{repo.name}</span>
									</div>
									<div className="flex items-center gap-1">
										<Badge
											variant={repo.is_active ? "default" : "secondary"}
											className="text-xs"
										>
											{repo.is_active ? "Active" : "Inactive"}
										</Badge>
										<Button
											variant="ghost"
											size="sm"
											aria-label={`Remove ${repo.name}`}
											className="text-muted-foreground hover:text-destructive"
											onClick={() => deleteMutation.mutate(repo.id)}
											disabled={deleteMutation.isPending}
										>
											<Trash2 className="h-4 w-4" />
										</Button>
									</div>
								</CardTitle>
								{repo.description && (
									<CardDescription className="line-clamp-2 text-xs">
										{repo.description}
									</CardDescription>
								)}
							</CardHeader>
							<CardContent>
								<a
									href={repo.url.replace(/\.git$/, "")}
									target="_blank"
									rel="noopener noreferrer"
									className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
								>
									{repo.url}
									<ExternalLink className="h-3 w-3" />
								</a>
								<div className="mt-2 text-xs text-muted-foreground">
									{repo.last_synced_at ? (
										<span suppressHydrationWarning>
											Last synced {formatDateTime(repo.last_synced_at)}
										</span>
									) : (
										"Never synced"
									)}
									{" \u00b7 "}
									<span suppressHydrationWarning>
										Added {formatDateTime(repo.created_at)}
									</span>
								</div>
							</CardContent>
						</Card>
					))}
				</div>
			)}
		</div>
	);
}

function AddRepoDialog() {
	const [open, setOpen] = useState(false);
	const [url, setUrl] = useState("");
	const [name, setName] = useState("");
	const [description, setDescription] = useState("");
	const queryClient = useQueryClient();

	const addMutation = useMutation({
		mutationFn: () =>
			api.post<AutoPkgRepoRead>("/autopkg/repos", {
				url,
				name:
					name ||
					url
						.split("/")
						.pop()
						?.replace(/\.git$/, "") ||
					"repo",
				description: description || null,
				is_active: true,
			}),
		onSuccess: () => {
			toast.success("Repo added");
			queryClient.invalidateQueries({ queryKey: ["autopkg-repos"] });
			setOpen(false);
			setUrl("");
			setName("");
			setDescription("");
		},
		onError: (err: Error) => toast.error(err.message),
	});

	const inferName = (repoUrl: string) => {
		const parts = repoUrl.split("/");
		const last = parts.pop()?.replace(/\.git$/, "");
		if (last && !name) setName(last);
	};

	return (
		<Dialog open={open} onOpenChange={setOpen}>
			<DialogTrigger asChild>
				<Button>
					<Plus className="mr-2 h-4 w-4" />
					Add Repo
				</Button>
			</DialogTrigger>
			<DialogContent>
				<DialogHeader>
					<DialogTitle>Add AutoPkg Recipe Repo</DialogTitle>
					<DialogDescription>
						Add a GitHub recipe repository URL. This will be used by the AutoPkg
						runner.
					</DialogDescription>
				</DialogHeader>
				<div className="space-y-4">
					<div className="space-y-2">
						<Label htmlFor="repo-url">Repository URL</Label>
						<Input
							id="repo-url"
							placeholder="https://github.com/autopkg/recipes.git"
							value={url}
							onChange={(e) => {
								setUrl(e.target.value);
								inferName(e.target.value);
							}}
						/>
					</div>
					<div className="space-y-2">
						<Label htmlFor="repo-name">Name</Label>
						<Input
							id="repo-name"
							placeholder="recipes"
							value={name}
							onChange={(e) => setName(e.target.value)}
						/>
					</div>
					<div className="space-y-2">
						<Label htmlFor="repo-desc">Description (optional)</Label>
						<Input
							id="repo-desc"
							placeholder="Official AutoPkg recipes"
							value={description}
							onChange={(e) => setDescription(e.target.value)}
						/>
					</div>
				</div>
				<DialogFooter>
					<Button variant="outline" onClick={() => setOpen(false)}>
						Cancel
					</Button>
					<Button
						onClick={() => addMutation.mutate()}
						disabled={!url || addMutation.isPending}
					>
						{addMutation.isPending ? "Adding..." : "Add Repo"}
					</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
}
