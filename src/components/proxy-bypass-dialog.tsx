"use client";

import { invoke } from "@tauri-apps/api/core";
import * as React from "react";
import { useTranslation } from "react-i18next";
import {
  LuChevronRight,
  LuCircleCheck,
  LuPlus,
  LuTriangleAlert,
  LuX,
} from "react-icons/lu";
import { toast } from "sonner";
import {
  AnimatedDisclosureChevron,
  AnimatedDisclosureContent,
} from "@/components/ui/animated-disclosure";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { translateBackendError } from "@/lib/backend-errors";
import { cn } from "@/lib/utils";

/** Mirrors `BypassRuleReport` in `src-tauri/src/proxy_bypass.rs`. */
interface BypassRuleReport {
  rule: string;
  canonical: string | null;
  kind: string | null;
  error_code: string | null;
  matches_target: boolean | null;
}

/** The shapes `parse_rule` can produce, mapped to their translated labels. */
const KIND_LABEL_KEYS: Record<string, string> = {
  domain: "proxyBypass.kinds.domain",
  subdomains: "proxyBypass.kinds.subdomains",
  wildcard: "proxyBypass.kinds.wildcard",
  ip: "proxyBypass.kinds.ip",
  cidr: "proxyBypass.kinds.cidr",
  local: "proxyBypass.kinds.local",
  loopback: "proxyBypass.kinds.loopback",
  regex: "proxyBypass.kinds.regex",
};

/** The error codes `BypassRuleError` emits, mapped to their reasons. */
const ERROR_LABEL_KEYS: Record<string, string> = {
  BYPASS_RULE_EMPTY: "proxyBypass.errors.empty",
  BYPASS_RULE_INVALID_HOST: "proxyBypass.errors.invalidHost",
  BYPASS_RULE_INVALID_PORT: "proxyBypass.errors.invalidPort",
  BYPASS_RULE_INVALID_CIDR: "proxyBypass.errors.invalidCidr",
  BYPASS_RULE_INVALID_SCHEME: "proxyBypass.errors.invalidScheme",
  BYPASS_RULE_INVALID_REGEX: "proxyBypass.errors.invalidRegex",
};

const SYNTAX_EXAMPLES = [
  { pattern: "example.com", key: "proxyBypass.syntax.domain" },
  { pattern: "*.example.com", key: "proxyBypass.syntax.subdomains" },
  { pattern: "192.168.1.5", key: "proxyBypass.syntax.ip" },
  { pattern: "10.0.0.0/8", key: "proxyBypass.syntax.cidr" },
  { pattern: "example.com:8080", key: "proxyBypass.syntax.port" },
  { pattern: "http://example.com", key: "proxyBypass.syntax.scheme" },
  { pattern: "<local>", key: "proxyBypass.syntax.local" },
  { pattern: "/example\\.(com|net)/", key: "proxyBypass.syntax.regex" },
] as const;

/** One pasted blob becomes many rules — people arrive with a NO_PROXY string. */
function splitDraft(draft: string): string[] {
  return draft
    .split(/[\s,;]+/)
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

interface ProxyBypassDialogProps {
  isOpen: boolean;
  onClose: () => void;
  profileId: string | null;
  profileName?: string;
  initialRules?: string[];
}

export function ProxyBypassDialog({
  isOpen,
  onClose,
  profileId,
  profileName,
  initialRules,
}: ProxyBypassDialogProps) {
  const { t } = useTranslation();
  const [rules, setRules] = React.useState<string[]>([]);
  const [draft, setDraft] = React.useState("");
  const [target, setTarget] = React.useState("");
  const [reports, setReports] = React.useState<BypassRuleReport[]>([]);
  // Keyed by the draft it describes: without that, a report still in flight from
  // the previous keystroke could green-light adding a rule the user has already
  // replaced.
  const [draftReports, setDraftReports] = React.useState<{
    key: string;
    reports: BypassRuleReport[];
  }>({ key: "", reports: [] });
  const [isSaving, setIsSaving] = React.useState(false);
  const [showSyntax, setShowSyntax] = React.useState(false);

  // Seed once per opening. `initialRules` is a fresh array on every parent
  // render, so reacting to its identity would wipe a just-added rule.
  const seededFor = React.useRef<string | null>(null);
  React.useEffect(() => {
    if (!isOpen) {
      seededFor.current = null;
      return;
    }
    if (seededFor.current === profileId) return;
    seededFor.current = profileId;
    setRules(initialRules ?? []);
    setDraft("");
    setTarget("");
    setDraftReports({ key: "", reports: [] });
    setShowSyntax(false);
  }, [isOpen, profileId, initialRules]);

  // Re-check the saved rules whenever they or the test host change, so the
  // "would this go direct?" answer always reflects what is actually stored.
  React.useEffect(() => {
    if (!isOpen) return;
    let cancelled = false;
    const trimmedTarget = target.trim();
    void invoke<BypassRuleReport[]>("check_proxy_bypass_rules", {
      rules,
      target: trimmedTarget.length > 0 ? trimmedTarget : null,
    })
      .then((result) => {
        if (!cancelled) setReports(result);
      })
      .catch((error: unknown) => {
        console.error("Failed to check bypass rules:", error);
      });
    return () => {
      cancelled = true;
    };
  }, [isOpen, rules, target]);

  // The draft is checked separately so the user sees what a rule will mean
  // before committing it, and cannot add one the backend would reject.
  const draftParts = React.useMemo(() => splitDraft(draft), [draft]);
  const draftKey = draftParts.join("\n");
  React.useEffect(() => {
    if (draftParts.length === 0) {
      setDraftReports({ key: "", reports: [] });
      return;
    }
    let cancelled = false;
    const handle = setTimeout(() => {
      void invoke<BypassRuleReport[]>("check_proxy_bypass_rules", {
        rules: draftParts,
        target: null,
      })
        .then((result) => {
          if (!cancelled) setDraftReports({ key: draftKey, reports: result });
        })
        .catch((error: unknown) => {
          console.error("Failed to check bypass rule draft:", error);
        });
    }, 150);
    return () => {
      cancelled = true;
      clearTimeout(handle);
    };
  }, [draftParts, draftKey]);

  // Only trust a report that describes the draft as it stands right now.
  const currentDraftReports =
    draftReports.key === draftKey ? draftReports.reports : [];
  const invalidDraft = currentDraftReports.find((r) => r.error_code !== null);
  const canAdd =
    draftParts.length > 0 &&
    currentDraftReports.length === draftParts.length &&
    invalidDraft === undefined;

  const persist = React.useCallback(
    async (next: string[], previous: string[]) => {
      if (!profileId) return;
      setIsSaving(true);
      setRules(next);
      try {
        await invoke("update_profile_proxy_bypass_rules", {
          profileId,
          rules: next,
        });
      } catch (error: unknown) {
        setRules(previous);
        toast.error(translateBackendError(t, error));
      } finally {
        setIsSaving(false);
      }
    },
    [profileId, t],
  );

  const handleAdd = () => {
    if (!canAdd) return;
    const additions = currentDraftReports
      .map((report) => report.canonical ?? report.rule)
      .filter((rule) => !rules.includes(rule));
    setDraft("");
    setDraftReports({ key: "", reports: [] });
    if (additions.length === 0) return;
    void persist([...rules, ...additions], rules);
  };

  const handleRemove = (rule: string) => {
    void persist(
      rules.filter((r) => r !== rule),
      rules,
    );
  };

  const trimmedTarget = target.trim();
  const matchedRule =
    trimmedTarget.length > 0
      ? (reports.find((r) => r.matches_target === true)?.rule ?? null)
      : null;

  return (
    <Dialog
      open={isOpen}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="flex max-h-[85vh] flex-col sm:max-w-xl">
        <DialogHeader className="shrink-0">
          <DialogTitle>
            {profileName
              ? t("proxyBypass.titleForProfile", { name: profileName })
              : t("proxyBypass.title")}
          </DialogTitle>
        </DialogHeader>

        <ScrollArea className="min-h-0 flex-1">
          <div className="flex flex-col gap-4 py-1 pr-3">
            <p className="text-sm text-muted-foreground">
              {t("proxyBypass.description")}
            </p>

            <div className="flex flex-col gap-2">
              <div className="flex gap-2">
                <Input
                  value={draft}
                  onChange={(e) => {
                    setDraft(e.target.value);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      handleAdd();
                    }
                  }}
                  placeholder={t("proxyBypass.rulePlaceholder")}
                  aria-label={t("proxyBypass.ruleInputLabel")}
                  aria-invalid={invalidDraft !== undefined}
                  className={cn(
                    "flex-1 font-mono text-sm",
                    invalidDraft !== undefined && "border-destructive",
                  )}
                />
                <Button
                  size="sm"
                  onClick={handleAdd}
                  disabled={!canAdd || isSaving}
                >
                  <LuPlus className="mr-1 size-4" />
                  {t("proxyBypass.addRule")}
                </Button>
              </div>

              {invalidDraft !== undefined ? (
                <p className="flex items-center gap-1.5 text-xs text-destructive">
                  <LuTriangleAlert className="size-3.5 shrink-0" />
                  {t(
                    ERROR_LABEL_KEYS[invalidDraft.error_code ?? ""] ??
                      "proxyBypass.errors.invalidHost",
                    { rule: invalidDraft.rule },
                  )}
                </p>
              ) : currentDraftReports.length > 1 ? (
                <p className="text-xs text-muted-foreground">
                  {t("proxyBypass.willAddCount", {
                    count: currentDraftReports.length,
                  })}
                </p>
              ) : currentDraftReports.length === 1 &&
                currentDraftReports[0].kind ? (
                <p className="text-xs text-muted-foreground">
                  {t("proxyBypass.draftMeaning", {
                    rule:
                      currentDraftReports[0].canonical ??
                      currentDraftReports[0].rule,
                    meaning: t(
                      KIND_LABEL_KEYS[currentDraftReports[0].kind] ??
                        "proxyBypass.kinds.domain",
                    ),
                  })}
                </p>
              ) : null}
            </div>

            {rules.length === 0 ? (
              <p className="rounded-md border border-dashed px-3 py-6 text-center text-sm text-muted-foreground">
                {t("proxyBypass.noRules")}
              </p>
            ) : (
              <div className="flex flex-col gap-1.5">
                {rules.map((rule) => {
                  const report = reports.find((r) => r.rule === rule);
                  const isMatch = report?.matches_target === true;
                  return (
                    <div
                      key={rule}
                      className={cn(
                        "flex items-center justify-between gap-2 rounded-md border px-3 py-1.5 text-sm",
                        isMatch
                          ? "border-success bg-success/10"
                          : "border-transparent bg-muted",
                      )}
                    >
                      <span className="min-w-0 flex-1 truncate font-mono text-xs">
                        {rule}
                      </span>
                      {report?.kind ? (
                        <Badge
                          variant="outline"
                          className="shrink-0 px-1.5 py-0 text-[10px] leading-tight"
                        >
                          {t(
                            KIND_LABEL_KEYS[report.kind] ??
                              "proxyBypass.kinds.domain",
                          )}
                        </Badge>
                      ) : null}
                      <button
                        type="button"
                        onClick={() => {
                          handleRemove(rule);
                        }}
                        disabled={isSaving}
                        aria-label={t("proxyBypass.removeRule", { rule })}
                        className="shrink-0 text-muted-foreground transition-colors hover:text-destructive disabled:opacity-50"
                      >
                        <LuX className="size-3.5" />
                      </button>
                    </div>
                  );
                })}
              </div>
            )}

            <div className="flex flex-col gap-2 rounded-md border p-3">
              <p className="text-xs font-medium">
                {t("proxyBypass.testTitle")}
              </p>
              <Input
                value={target}
                onChange={(e) => {
                  setTarget(e.target.value);
                }}
                placeholder={t("proxyBypass.testPlaceholder")}
                aria-label={t("proxyBypass.testTitle")}
                className="font-mono text-sm"
              />
              {trimmedTarget.length > 0 &&
                (matchedRule !== null ? (
                  <p className="flex items-center gap-1.5 text-xs text-success">
                    <LuCircleCheck className="size-3.5 shrink-0" />
                    {t("proxyBypass.testDirect", { rule: matchedRule })}
                  </p>
                ) : (
                  <p className="text-xs text-muted-foreground">
                    {t("proxyBypass.testProxied")}
                  </p>
                ))}
            </div>

            <div>
              <button
                type="button"
                onClick={() => {
                  setShowSyntax((open) => !open);
                }}
                aria-expanded={showSyntax}
                className="flex items-center gap-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground"
              >
                <AnimatedDisclosureChevron open={showSyntax}>
                  <LuChevronRight className="size-3.5" />
                </AnimatedDisclosureChevron>
                {t("proxyBypass.syntaxTitle")}
              </button>
              <AnimatedDisclosureContent open={showSyntax}>
                <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 text-xs">
                  {SYNTAX_EXAMPLES.map((example) => (
                    <React.Fragment key={example.pattern}>
                      <dt className="font-mono text-foreground">
                        {example.pattern}
                      </dt>
                      <dd className="text-muted-foreground">
                        {t(example.key)}
                      </dd>
                    </React.Fragment>
                  ))}
                </dl>
              </AnimatedDisclosureContent>
            </div>
          </div>
        </ScrollArea>

        <DialogFooter className="shrink-0">
          <Button variant="outline" onClick={onClose}>
            {t("common.buttons.close")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
