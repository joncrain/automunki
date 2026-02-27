"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { ChevronDown, ChevronRight, Play, Search, X } from "lucide-react";
import { parseAsInteger, parseAsString, useQueryState } from "nuqs";
import { useState } from "react";
import { toast } from "sonner";
import { DataTable } from "@/components/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
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
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "@/components/ui/select";
import {
	type AutoPkgRecipeRead,
	type AutoPkgRunRead,
	api,
	type PaginatedResponse,
} from "@/lib/api";
import { formatDateTime } from "@/lib/format";

const STATUS_OPTIONS = [
	"pending",
	"running",
	"completed",
	"failed",
	"cancelled",
];

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

export default function AutoPkgRunsPage() {
	const [page, setPage] = useQueryState("page", parseAsInteger.withDefault(1));
	const [pageSize, setPageSize] = useQueryState(
		"pageSize",
		parseAsInteger.withDefault(20),
	);
	const [status, setStatus] = useQueryState(
		"status",
		parseAsString.withDefault(""),
	);
	const [expandedRun, setExpandedRun] = useState<string | null>(null);
	const queryClient = useQueryClient();

	const { data, isLoading } = useQuery({
		queryKey: ["autopkg-runs", page, pageSize, status],
		queryFn: () => {
			const params = new URLSearchParams();
			params.set("page", String(page));
			params.set("page_size", String(pageSize));
			if (status) params.set("status", status);
			return api.get<PaginatedResponse<AutoPkgRunRead>>(
				`/autopkg/runs?${params.toString()}`,
			);
		},
	});

	const triggerMutation = useMutation({
		mutationFn: (recipeNames: string[] | null) =>
			api.post<AutoPkgRunRead>("/autopkg/runs", {
				recipe_names: recipeNames,
			}),
		onSuccess: () => {
			toast.success("AutoPkg run triggered");
			queryClient.invalidateQueries({ queryKey: ["autopkg-runs"] });
		},
		onError: (err: Error) =>
			toast.error(`Failed to trigger run: ${err.message}`),
	});

	const columns: ColumnDef<AutoPkgRunRead>[] = [
		{
			id: "expand",
			cell: ({ row }) => (
				<Button
					variant="ghost"
					size="sm"
					aria-label={
						expandedRun === row.original.id ? "Collapse run" : "Expand run"
					}
					onClick={() =>
						setExpandedRun(
							expandedRun === row.original.id ? null : row.original.id,
						)
					}
				>
					{expandedRun === row.original.id ? (
						<ChevronDown className="h-4 w-4" />
					) : (
						<ChevronRight className="h-4 w-4" />
					)}
				</Button>
			),
		},
		{
			accessorKey: "status",
			header: "Status",
			cell: ({ row }) => (
				<Badge variant={statusVariant(row.original.status)}>
					{row.original.status}
				</Badge>
			),
		},
		{
			accessorKey: "trigger_type",
			header: "Trigger",
			cell: ({ row }) => (
				<Badge variant="outline">{row.original.trigger_type}</Badge>
			),
		},
		{
			accessorKey: "triggered_by",
			header: "Triggered By",
		},
		{
			id: "stats",
			header: "Results",
			cell: ({ row }) => {
				const r = row.original;
				if (!r.total_recipes) return "—";
				return (
					<div className="flex gap-2">
						{r.recipes_imported ? (
							<Badge variant="default">{r.recipes_imported} imported</Badge>
						) : null}
						{r.recipes_failed ? (
							<Badge variant="destructive">{r.recipes_failed} failed</Badge>
						) : null}
						<span className="text-sm text-muted-foreground">
							{r.total_recipes} total
						</span>
					</div>
				);
			},
		},
		{
			accessorKey: "created_at",
			header: "Date",
			cell: ({ row }) => (
				<span suppressHydrationWarning className="text-sm">
					{formatDateTime(row.original.created_at)}
				</span>
			),
		},
	];

	return (
		<div className="flex h-[calc(100vh-3rem)] flex-col gap-4">
			<div className="flex items-center justify-between">
				<h1 className="text-3xl font-bold">AutoPkg Runs</h1>
				<TriggerRunDialog
					onTrigger={(recipeNames) => triggerMutation.mutate(recipeNames)}
					isPending={triggerMutation.isPending}
				/>
			</div>

			<div className="flex flex-wrap items-center gap-2">
				<Select
					value={status || "_all"}
					onValueChange={(v) => {
						setStatus(v === "_all" ? null : v);
						setPage(1);
					}}
				>
					<SelectTrigger className="w-[150px]">
						<SelectValue placeholder="Status" />
					</SelectTrigger>
					<SelectContent>
						<SelectItem value="_all">All Statuses</SelectItem>
						{STATUS_OPTIONS.map((s) => (
							<SelectItem key={s} value={s}>
								{s}
							</SelectItem>
						))}
					</SelectContent>
				</Select>

				{status && (
					<Button
						variant="ghost"
						size="sm"
						aria-label="Clear filters"
						onClick={() => {
							setStatus(null);
							setPage(1);
						}}
					>
						<X className="mr-1 h-4 w-4" />
						Clear
					</Button>
				)}
			</div>

			<div className="flex-1 min-h-0">
				<DataTable
					columns={columns}
					data={data?.items ?? []}
					pageCount={data?.total_pages ?? 1}
					page={page}
					pageSize={pageSize}
					total={data?.total}
					onPageChange={setPage}
					onPageSizeChange={(size) => {
						setPageSize(size);
						setPage(1);
					}}
					isLoading={isLoading}
				/>
			</div>

			{expandedRun &&
				data?.items &&
				(() => {
					const run = data.items.find((r) => r.id === expandedRun);
					return run ? <RunDetail run={run} /> : null;
				})()}
		</div>
	);
}

function TriggerRunDialog({
	onTrigger,
	isPending,
}: {
	onTrigger: (recipeNames: string[] | null) => void;
	isPending: boolean;
}) {
	const [open, setOpen] = useState(false);
	const [selected, setSelected] = useState<Set<string>>(new Set());
	const [recipeSearch, setRecipeSearch] = useState("");

	const { data: recipes } = useQuery({
		queryKey: ["autopkg-recipes-enabled"],
		queryFn: () =>
			api.get<AutoPkgRecipeRead[]>("/autopkg/recipes?enabled_only=true"),
		enabled: open,
	});

	const filtered = (recipes ?? []).filter((r) =>
		recipeSearch
			? r.name.toLowerCase().includes(recipeSearch.toLowerCase()) ||
				r.identifier.toLowerCase().includes(recipeSearch.toLowerCase())
			: true,
	);

	const toggleRecipe = (name: string) => {
		setSelected((prev) => {
			const next = new Set(prev);
			if (next.has(name)) next.delete(name);
			else next.add(name);
			return next;
		});
	};

	const toggleAll = () => {
		if (selected.size === filtered.length) {
			setSelected(new Set());
		} else {
			setSelected(new Set(filtered.map((r) => r.name)));
		}
	};

	const handleTrigger = () => {
		const names = selected.size > 0 ? Array.from(selected) : null;
		onTrigger(names);
		setOpen(false);
		setSelected(new Set());
		setRecipeSearch("");
	};

	return (
		<Dialog open={open} onOpenChange={setOpen}>
			<DialogTrigger asChild>
				<Button>
					<Play className="mr-2 h-4 w-4" />
					Trigger Run
				</Button>
			</DialogTrigger>
			<DialogContent className="max-h-[80vh] sm:max-w-lg">
				<DialogHeader>
					<DialogTitle>Trigger AutoPkg Run</DialogTitle>
					<DialogDescription>
						Select specific recipes or run all enabled recipes.
					</DialogDescription>
				</DialogHeader>

				<div className="space-y-3">
					<div className="relative">
						<Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
						<Input
							placeholder="Filter recipes..."
							value={recipeSearch}
							onChange={(e) => setRecipeSearch(e.target.value)}
							className="pl-9"
						/>
					</div>

					<div className="flex items-center justify-between px-1">
						<button
							type="button"
							className="flex cursor-pointer items-center gap-2 text-sm"
							onClick={toggleAll}
						>
							<Checkbox
								checked={
									filtered.length > 0 && selected.size === filtered.length
								}
								onCheckedChange={toggleAll}
								aria-label="Select all recipes"
							/>
							Select all ({filtered.length})
						</button>
						{selected.size > 0 && (
							<span className="text-sm text-muted-foreground">
								{selected.size} selected
							</span>
						)}
					</div>

					<div className="max-h-[40vh] space-y-1 overflow-y-auto rounded-md border p-2">
						{filtered.length === 0 ? (
							<p className="py-4 text-center text-sm text-muted-foreground">
								No enabled recipes found.
							</p>
						) : (
							filtered.map((recipe) => (
								<button
									type="button"
									key={recipe.id}
									className="flex w-full cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-left hover:bg-accent"
									onClick={() => toggleRecipe(recipe.name)}
								>
									<Checkbox
										checked={selected.has(recipe.name)}
										onCheckedChange={() => toggleRecipe(recipe.name)}
									/>
									<span className="flex-1 truncate text-sm">{recipe.name}</span>
									{recipe.last_run_status && (
										<Badge
											variant={
												recipe.last_run_status === "success"
													? "default"
													: "destructive"
											}
											className="text-xs"
										>
											{recipe.last_run_status}
										</Badge>
									)}
								</button>
							))
						)}
					</div>
				</div>

				<DialogFooter>
					<Button variant="outline" onClick={() => setOpen(false)}>
						Cancel
					</Button>
					<Button onClick={handleTrigger} disabled={isPending}>
						<Play className="mr-1 h-4 w-4" />
						{isPending
							? "Triggering..."
							: selected.size > 0
								? `Run ${selected.size} Recipe${selected.size > 1 ? "s" : ""}`
								: "Run All Enabled"}
					</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
}

function RunDetail({ run }: { run: AutoPkgRunRead }) {
	if (!run?.results?.length) {
		return (
			<Card>
				<CardContent className="p-4">
					<p className="text-muted-foreground">No results for this run</p>
				</CardContent>
			</Card>
		);
	}

	const statusVariantResult = (s: string) => {
		switch (s) {
			case "success":
			case "imported":
				return "default" as const;
			case "failed":
			case "trust_failed":
				return "destructive" as const;
			default:
				return "secondary" as const;
		}
	};

	return (
		<Card>
			<CardHeader>
				<CardTitle>Run Results</CardTitle>
			</CardHeader>
			<CardContent>
				<div className="space-y-2">
					{run.results.map((result) => (
						<div
							key={result.id}
							className="flex items-center justify-between rounded-md border p-3"
						>
							<div className="flex items-center gap-3">
								<Badge variant={statusVariantResult(result.status)}>
									{result.status}
								</Badge>
								<span className="font-medium">{result.recipe_name}</span>
								{result.imported_version && (
									<span className="text-sm text-muted-foreground">
										v{result.imported_version}
									</span>
								)}
							</div>
							<div className="flex items-center gap-2">
								<Badge
									variant={
										result.approval_status === "approved" ||
										result.approval_status === "auto_approved"
											? "default"
											: result.approval_status === "pending"
												? "secondary"
												: "destructive"
									}
								>
									{result.approval_status}
								</Badge>
								{result.duration_seconds != null && (
									<span className="text-sm text-muted-foreground">
										{result.duration_seconds}s
									</span>
								)}
							</div>
						</div>
					))}
				</div>
			</CardContent>
		</Card>
	);
}
