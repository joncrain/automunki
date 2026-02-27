"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import {
	Compass,
	GripVertical,
	Pencil,
	Plus,
	Search,
	Trash2,
	X,
} from "lucide-react";
import Link from "next/link";
import { parseAsString, useQueryState } from "nuqs";
import { useState } from "react";
import { toast } from "sonner";
import { DataTable } from "@/components/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { type AutoPkgRecipeRead, api, type CatalogRead } from "@/lib/api";

function makeColumns(
	onToggleEnabled: (id: string, enabled: boolean) => void,
	onToggleAutoPromote: (id: string, auto: boolean) => void,
	onEdit: (recipe: AutoPkgRecipeRead) => void,
): ColumnDef<AutoPkgRecipeRead>[] {
	return [
		{
			accessorKey: "name",
			header: "Name",
			cell: ({ row }) => (
				<div>
					<span className="font-medium">{row.original.name}</span>
					{row.original.is_override && (
						<Badge variant="outline" className="ml-2 text-xs">
							Override
						</Badge>
					)}
				</div>
			),
		},
		{
			accessorKey: "identifier",
			header: "Identifier",
			cell: ({ row }) => (
				<span className="truncate font-mono text-sm text-muted-foreground">
					{row.original.identifier}
				</span>
			),
		},
		{
			accessorKey: "is_enabled",
			header: "Enabled",
			cell: ({ row }) => (
				<Switch
					checked={row.original.is_enabled}
					onCheckedChange={(checked) =>
						onToggleEnabled(row.original.id, checked)
					}
					aria-label={`Toggle ${row.original.name} enabled`}
				/>
			),
		},
		{
			accessorKey: "auto_promote",
			header: "Auto Promote",
			cell: ({ row }) => (
				<Switch
					checked={row.original.auto_promote}
					onCheckedChange={(checked) =>
						onToggleAutoPromote(row.original.id, checked)
					}
					aria-label={`Toggle ${row.original.name} auto-promote`}
				/>
			),
		},
		{
			accessorKey: "target_catalogs",
			header: "Target Catalogs",
			cell: ({ row }) => (
				<div className="flex gap-1">
					{row.original.target_catalogs?.map((c) => (
						<Badge key={c} variant="secondary">
							{c}
						</Badge>
					)) ?? "—"}
				</div>
			),
		},
		{
			accessorKey: "last_run_status",
			header: "Last Run",
			cell: ({ row }) =>
				row.original.last_run_status ? (
					<Badge
						variant={
							row.original.last_run_status === "success"
								? "default"
								: "destructive"
						}
					>
						{row.original.last_run_status}
					</Badge>
				) : (
					"—"
				),
		},
		{
			id: "actions",
			header: "",
			cell: ({ row }) => (
				<Button
					variant="ghost"
					size="sm"
					aria-label={`Edit ${row.original.name}`}
					onClick={() => onEdit(row.original)}
				>
					<Pencil className="h-4 w-4" />
				</Button>
			),
		},
	];
}

export default function RecipesPage() {
	const queryClient = useQueryClient();
	const [search, setSearch] = useQueryState(
		"search",
		parseAsString.withDefault(""),
	);
	const [enabled, setEnabled] = useQueryState(
		"enabled",
		parseAsString.withDefault(""),
	);
	const [editingRecipe, setEditingRecipe] = useState<AutoPkgRecipeRead | null>(
		null,
	);

	const { data: recipes, isLoading } = useQuery({
		queryKey: ["autopkg-recipes"],
		queryFn: () => api.get<AutoPkgRecipeRead[]>("/autopkg/recipes"),
	});

	const updateMutation = useMutation({
		mutationFn: ({ id, ...data }: { id: string } & Record<string, unknown>) =>
			api.put(`/autopkg/recipes/${id}`, data),
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["autopkg-recipes"] });
		},
		onError: (err: Error) => toast.error(err.message),
	});

	const onToggleEnabled = (id: string, val: boolean) =>
		updateMutation.mutate({ id, is_enabled: val });

	const onToggleAutoPromote = (id: string, val: boolean) =>
		updateMutation.mutate({ id, auto_promote: val });

	const columns = makeColumns(
		onToggleEnabled,
		onToggleAutoPromote,
		setEditingRecipe,
	);

	const filtered = (recipes ?? []).filter((r) => {
		if (search) {
			const q = search.toLowerCase();
			if (
				!r.name.toLowerCase().includes(q) &&
				!r.identifier.toLowerCase().includes(q)
			)
				return false;
		}
		if (enabled === "true" && !r.is_enabled) return false;
		if (enabled === "false" && r.is_enabled) return false;
		return true;
	});

	const hasFilters = search || enabled;

	return (
		<div className="flex h-[calc(100vh-3rem)] flex-col gap-4">
			<div className="flex items-center justify-between">
				<h1 className="text-3xl font-bold">Recipe Management</h1>
				<Button variant="outline" asChild>
					<Link href="/autopkg/discover">
						<Compass className="mr-2 h-4 w-4" />
						Discover Recipes
					</Link>
				</Button>
			</div>

			<div className="flex flex-wrap items-center gap-2">
				<div className="relative flex-1 max-w-sm">
					<Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
					<Input
						placeholder="Search recipes..."
						value={search}
						onChange={(e) => setSearch(e.target.value || null)}
						className="pl-9"
					/>
				</div>

				<Select
					value={enabled || "_all"}
					onValueChange={(v) => setEnabled(v === "_all" ? null : v)}
				>
					<SelectTrigger className="w-[140px]">
						<SelectValue placeholder="Status" />
					</SelectTrigger>
					<SelectContent>
						<SelectItem value="_all">All</SelectItem>
						<SelectItem value="true">Enabled</SelectItem>
						<SelectItem value="false">Disabled</SelectItem>
					</SelectContent>
				</Select>

				{hasFilters && (
					<Button
						variant="ghost"
						size="sm"
						aria-label="Clear filters"
						onClick={() => {
							setSearch(null);
							setEnabled(null);
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
					data={filtered}
					total={filtered.length}
					isLoading={isLoading}
				/>
			</div>

			{editingRecipe && (
				<RecipeEditDialog
					recipe={editingRecipe}
					onClose={() => setEditingRecipe(null)}
					onSaved={() => {
						queryClient.invalidateQueries({
							queryKey: ["autopkg-recipes"],
						});
						setEditingRecipe(null);
					}}
				/>
			)}
		</div>
	);
}

// ── Structured key/value editor ──────────────────────────────────────────

type KVEntry = { id: string; key: string; value: string };

let _kvId = 0;
function nextKvId() {
	return `kv-${++_kvId}`;
}

function kvFromDict(
	dict: Record<string, unknown> | null | undefined,
): KVEntry[] {
	if (!dict || typeof dict !== "object") return [];
	return Object.entries(dict).map(([key, value]) => ({
		id: nextKvId(),
		key,
		value: typeof value === "string" ? value : JSON.stringify(value),
	}));
}

function kvToDict(entries: KVEntry[]): Record<string, unknown> {
	const result: Record<string, unknown> = {};
	for (const { key, value } of entries) {
		if (!key.trim()) continue;
		try {
			result[key.trim()] = JSON.parse(value);
		} catch {
			result[key.trim()] = value;
		}
	}
	return result;
}

function KeyValueEditor({
	entries,
	onChange,
	keyPlaceholder = "KEY",
	valuePlaceholder = "Value",
	readOnly = false,
}: {
	entries: KVEntry[];
	onChange: (entries: KVEntry[]) => void;
	keyPlaceholder?: string;
	valuePlaceholder?: string;
	readOnly?: boolean;
}) {
	const update = (index: number, field: "key" | "value", val: string) => {
		const next = [...entries];
		next[index] = { ...next[index], [field]: val };
		onChange(next);
	};

	const remove = (index: number) => {
		onChange(entries.filter((_, i) => i !== index));
	};

	const add = () => {
		onChange([...entries, { id: nextKvId(), key: "", value: "" }]);
	};

	return (
		<div className="space-y-2">
			{entries.length === 0 && !readOnly && (
				<p className="text-xs text-muted-foreground py-1">
					No entries. Click + to add one.
				</p>
			)}
			{entries.length === 0 && readOnly && (
				<p className="text-xs text-muted-foreground py-1">No entries.</p>
			)}
			{entries.map((entry, i) => (
				<div key={entry.id} className="flex items-start gap-2">
					{!readOnly && (
						<GripVertical className="mt-2.5 h-4 w-4 shrink-0 text-muted-foreground/50" />
					)}
					<Input
						value={entry.key}
						onChange={(e) => update(i, "key", e.target.value)}
						placeholder={keyPlaceholder}
						className="font-mono text-sm flex-[2]"
						readOnly={readOnly}
					/>
					<Input
						value={entry.value}
						onChange={(e) => update(i, "value", e.target.value)}
						placeholder={valuePlaceholder}
						className="font-mono text-sm flex-[3]"
						readOnly={readOnly}
					/>
					{!readOnly && (
						<Button
							type="button"
							variant="ghost"
							size="sm"
							className="shrink-0 mt-0.5"
							aria-label={`Remove ${entry.key}`}
							onClick={() => remove(i)}
						>
							<Trash2 className="h-4 w-4 text-destructive" />
						</Button>
					)}
				</div>
			))}
			{!readOnly && (
				<Button
					type="button"
					variant="outline"
					size="sm"
					onClick={add}
					className="w-full"
				>
					<Plus className="mr-1 h-4 w-4" />
					Add Entry
				</Button>
			)}
		</div>
	);
}

// ── Trust info viewer ────────────────────────────────────────────────────

function TrustInfoViewer({
	trustInfo,
}: {
	trustInfo: Record<string, unknown> | null | undefined;
}) {
	if (!trustInfo) {
		return (
			<p className="text-sm text-muted-foreground py-2">
				No trust info recorded. Run{" "}
				<code className="bg-muted px-1 rounded text-xs">
					autopkg update-trust-info
				</code>{" "}
				to generate.
			</p>
		);
	}

	const parentRecipes =
		(trustInfo.parent_recipes as Record<string, Record<string, string>>) ?? {};
	const processors =
		(trustInfo.non_core_processors as Record<string, Record<string, string>>) ??
		{};

	return (
		<div className="space-y-4">
			<div>
				<h4 className="text-sm font-medium mb-2">Parent Recipes</h4>
				{Object.keys(parentRecipes).length === 0 ? (
					<p className="text-xs text-muted-foreground">None</p>
				) : (
					<div className="space-y-2">
						{Object.entries(parentRecipes).map(([identifier, info]) => (
							<div
								key={identifier}
								className="rounded-md border bg-muted/30 px-3 py-2"
							>
								<p className="font-mono text-sm font-medium">{identifier}</p>
								<div className="mt-1 grid gap-1 text-xs text-muted-foreground">
									<span>
										Path:{" "}
										<code className="bg-muted px-1 rounded">{info.path}</code>
									</span>
									<span className="truncate">
										SHA256:{" "}
										<code className="bg-muted px-1 rounded">
											{info.sha256_hash}
										</code>
									</span>
									{info.git_hash && (
										<span className="truncate">
											Git:{" "}
											<code className="bg-muted px-1 rounded">
												{info.git_hash}
											</code>
										</span>
									)}
								</div>
							</div>
						))}
					</div>
				)}
			</div>

			<div>
				<h4 className="text-sm font-medium mb-2">Non-Core Processors</h4>
				{Object.keys(processors).length === 0 ? (
					<p className="text-xs text-muted-foreground">None</p>
				) : (
					<div className="space-y-2">
						{Object.entries(processors).map(([name, info]) => (
							<div
								key={name}
								className="rounded-md border bg-muted/30 px-3 py-2"
							>
								<p className="font-mono text-sm font-medium">{name}</p>
								<div className="mt-1 grid gap-1 text-xs text-muted-foreground">
									<span>
										Path:{" "}
										<code className="bg-muted px-1 rounded">{info.path}</code>
									</span>
									<span className="truncate">
										SHA256:{" "}
										<code className="bg-muted px-1 rounded">
											{info.sha256_hash}
										</code>
									</span>
									{info.git_hash && (
										<span className="truncate">
											Git:{" "}
											<code className="bg-muted px-1 rounded">
												{info.git_hash}
											</code>
										</span>
									)}
								</div>
							</div>
						))}
					</div>
				)}
			</div>
		</div>
	);
}

// ── Recipe edit dialog ───────────────────────────────────────────────────

function RecipeEditDialog({
	recipe,
	onClose,
	onSaved,
}: {
	recipe: AutoPkgRecipeRead;
	onClose: () => void;
	onSaved: () => void;
}) {
	const [identifier, setIdentifier] = useState(recipe.identifier);
	const [name, setName] = useState(recipe.name);
	const [parentRecipe, setParentRecipe] = useState(recipe.parent_recipe ?? "");
	const [isEnabled, setIsEnabled] = useState(recipe.is_enabled);
	const [isOverride, setIsOverride] = useState(recipe.is_override);
	const [autoPromote, setAutoPromote] = useState(recipe.auto_promote);
	const [targetCatalogs, setTargetCatalogs] = useState(
		(recipe.target_catalogs ?? []).join(", "),
	);
	const [inputVars, setInputVars] = useState<KVEntry[]>(
		kvFromDict(recipe.input_variables as Record<string, unknown> | null),
	);
	const [overrideEntries, setOverrideEntries] = useState<KVEntry[]>(
		kvFromDict(recipe.override_data as Record<string, unknown> | null),
	);

	const { data: catalogs } = useQuery({
		queryKey: ["catalogs"],
		queryFn: () => api.get<CatalogRead[]>("/catalogs"),
	});

	const saveMutation = useMutation({
		mutationFn: (payload: Record<string, unknown>) =>
			api.put(`/autopkg/recipes/${recipe.id}`, payload),
		onSuccess: () => {
			toast.success(`Recipe ${name} updated`);
			onSaved();
		},
		onError: (err: Error) => toast.error(err.message),
	});

	const handleSave = () => {
		const payload: Record<string, unknown> = {
			identifier,
			name,
			parent_recipe: parentRecipe || null,
			is_enabled: isEnabled,
			is_override: isOverride,
			auto_promote: autoPromote,
			target_catalogs: targetCatalogs
				? targetCatalogs
						.split(",")
						.map((s) => s.trim())
						.filter(Boolean)
				: null,
			input_variables: inputVars.length > 0 ? kvToDict(inputVars) : null,
			override_data:
				overrideEntries.length > 0 ? kvToDict(overrideEntries) : null,
		};

		saveMutation.mutate(payload);
	};

	const catalogNames = (catalogs ?? []).map((c) => c.name);

	return (
		<Dialog open onOpenChange={() => onClose()}>
			<DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
				<DialogHeader>
					<DialogTitle>Edit Recipe: {recipe.name}</DialogTitle>
					<DialogDescription>
						Modify the recipe override settings. Changes are saved to the
						database.
					</DialogDescription>
				</DialogHeader>

				<Tabs defaultValue="general" className="w-full">
					<TabsList className="w-full grid grid-cols-4">
						<TabsTrigger value="general">General</TabsTrigger>
						<TabsTrigger value="input">
							Input
							{inputVars.length > 0 && (
								<Badge variant="secondary" className="ml-1.5 text-xs px-1.5">
									{inputVars.length}
								</Badge>
							)}
						</TabsTrigger>
						<TabsTrigger value="overrides">
							Overrides
							{overrideEntries.length > 0 && (
								<Badge variant="secondary" className="ml-1.5 text-xs px-1.5">
									{overrideEntries.length}
								</Badge>
							)}
						</TabsTrigger>
						<TabsTrigger value="trust">Trust Info</TabsTrigger>
					</TabsList>

					<TabsContent value="general" className="space-y-4 mt-4">
						<div className="grid gap-4 sm:grid-cols-2">
							<div className="space-y-2">
								<Label htmlFor="recipe-name">Name</Label>
								<Input
									id="recipe-name"
									value={name}
									onChange={(e) => setName(e.target.value)}
								/>
							</div>
							<div className="space-y-2">
								<Label htmlFor="recipe-identifier">Identifier</Label>
								<Input
									id="recipe-identifier"
									value={identifier}
									onChange={(e) => setIdentifier(e.target.value)}
									className="font-mono text-sm"
								/>
							</div>
						</div>

						<div className="space-y-2">
							<Label htmlFor="recipe-parent">Parent Recipe</Label>
							<Input
								id="recipe-parent"
								value={parentRecipe}
								onChange={(e) => setParentRecipe(e.target.value)}
								placeholder="com.github.autopkg.munki.Firefox"
								className="font-mono text-sm"
							/>
						</div>

						<div className="grid gap-4 sm:grid-cols-3">
							<div className="flex items-center gap-3 rounded-md border px-3 py-2">
								<Switch
									id="recipe-enabled"
									checked={isEnabled}
									onCheckedChange={setIsEnabled}
								/>
								<Label htmlFor="recipe-enabled" className="cursor-pointer">
									Enabled
								</Label>
							</div>
							<div className="flex items-center gap-3 rounded-md border px-3 py-2">
								<Switch
									id="recipe-override"
									checked={isOverride}
									onCheckedChange={setIsOverride}
								/>
								<Label htmlFor="recipe-override" className="cursor-pointer">
									Override
								</Label>
							</div>
							<div className="flex items-center gap-3 rounded-md border px-3 py-2">
								<Switch
									id="recipe-auto-promote"
									checked={autoPromote}
									onCheckedChange={setAutoPromote}
								/>
								<Label htmlFor="recipe-auto-promote" className="cursor-pointer">
									Auto Promote
								</Label>
							</div>
						</div>

						<div className="space-y-2">
							<Label htmlFor="recipe-catalogs">Target Catalogs</Label>
							<div className="flex flex-wrap gap-1 mb-2">
								{catalogNames.map((cat) => {
									const selected = targetCatalogs
										.split(",")
										.map((s) => s.trim())
										.includes(cat);
									return (
										<Badge
											key={cat}
											variant={selected ? "default" : "outline"}
											className="cursor-pointer"
											onClick={() => {
												const current = targetCatalogs
													.split(",")
													.map((s) => s.trim())
													.filter(Boolean);
												const next = selected
													? current.filter((c) => c !== cat)
													: [...current, cat];
												setTargetCatalogs(next.join(", "));
											}}
										>
											{cat}
										</Badge>
									);
								})}
							</div>
							<Input
								id="recipe-catalogs"
								value={targetCatalogs}
								onChange={(e) => setTargetCatalogs(e.target.value)}
								placeholder="testing, production"
							/>
						</div>
					</TabsContent>

					<TabsContent value="input" className="mt-4">
						<div className="space-y-2">
							<div className="flex items-center justify-between">
								<Label>Input Variables</Label>
								<span className="text-xs text-muted-foreground">
									Key/value pairs passed to the recipe (e.g. NAME,
									MUNKI_REPO_SUBDIR)
								</span>
							</div>
							<KeyValueEditor
								entries={inputVars}
								onChange={setInputVars}
								keyPlaceholder="VARIABLE_NAME"
								valuePlaceholder="value"
							/>
						</div>
					</TabsContent>

					<TabsContent value="overrides" className="mt-4">
						<div className="space-y-2">
							<div className="flex items-center justify-between">
								<Label>Override Data</Label>
								<span className="text-xs text-muted-foreground">
									Additional override-specific settings
								</span>
							</div>
							<KeyValueEditor
								entries={overrideEntries}
								onChange={setOverrideEntries}
								keyPlaceholder="key"
								valuePlaceholder="value"
							/>
						</div>
					</TabsContent>

					<TabsContent value="trust" className="mt-4">
						<TrustInfoViewer
							trustInfo={recipe.trust_info as Record<string, unknown> | null}
						/>
					</TabsContent>
				</Tabs>

				<DialogFooter>
					<Button variant="outline" onClick={onClose}>
						Cancel
					</Button>
					<Button
						onClick={handleSave}
						disabled={saveMutation.isPending || !name || !identifier}
					>
						{saveMutation.isPending ? "Saving..." : "Save Changes"}
					</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
}
