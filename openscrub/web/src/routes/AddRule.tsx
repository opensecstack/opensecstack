import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useMutation } from "@tanstack/react-query";
import { Button } from "@/components/Button";
import { createRule, type CreateRuleInput, type RuleType } from "@/api/rules";
import { isValidCidr } from "@/lib/cidr";

const DEFAULT_TTL_SECONDS = 3600;

function isRuleType(s: string): s is RuleType {
  return s === "blocklist" || s === "ratelimit" || s === "syncookie";
}

export default function AddRule(): JSX.Element {
  const { t } = useTranslation(["common", "rules"]);
  const navigate = useNavigate();
  const [type, setType] = useState<RuleType>("blocklist");
  const [cidr, setCidr] = useState("");
  const [pps, setPps] = useState<string>("");
  const [port, setPort] = useState<string>("");
  const [ttl, setTtl] = useState<string>(String(DEFAULT_TTL_SECONDS));
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: createRule,
    onSuccess: () => navigate("/rules"),
    onError: (err: Error) => setError(err.message),
  });

  function onSubmit(e: FormEvent): void {
    e.preventDefault();
    setError(null);

    const ttlSeconds = ttl ? Number(ttl) : DEFAULT_TTL_SECONDS;
    if (!Number.isFinite(ttlSeconds) || ttlSeconds < 1) {
      setError(t("rules:errors.ttl_invalid"));
      return;
    }

    const payload: CreateRuleInput = { type, ttl_seconds: ttlSeconds };

    if (type === "blocklist" || type === "ratelimit") {
      if (!isValidCidr(cidr)) {
        setError(t("rules:errors.cidr_invalid"));
        return;
      }
      payload.cidr = cidr;
    }

    if (type === "ratelimit") {
      const ppsNum = Number(pps);
      if (!pps || !Number.isFinite(ppsNum) || ppsNum < 1) {
        setError(t("rules:errors.pps_required"));
        return;
      }
      payload.pps = ppsNum;
    }

    if (type === "syncookie") {
      const portNum = Number(port);
      if (!port || !Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
        setError(t("rules:errors.port_invalid"));
        return;
      }
      payload.port = portNum;
    }

    create.mutate(payload);
  }

  return (
    <div className="max-w-md bg-white rounded-md shadow-sm p-6">
      <h1 className="text-xl font-semibold mb-4">{t("rules:add_title")}</h1>
      <form onSubmit={onSubmit} className="space-y-3">
        <div>
          <label className="block text-sm mb-1">{t("rules:fields.type")}</label>
          <select
            value={type}
            onChange={(e) => {
              const v = e.target.value;
              if (isRuleType(v)) setType(v);
            }}
            className="w-full border border-slate-300 rounded-md px-2 py-1.5 text-sm"
          >
            <option value="blocklist">{t("rules:types.blocklist")}</option>
            <option value="ratelimit">{t("rules:types.ratelimit")}</option>
            <option value="syncookie">{t("rules:types.syncookie")}</option>
          </select>
        </div>

        {(type === "blocklist" || type === "ratelimit") && (
          <div>
            <label className="block text-sm mb-1">{t("rules:fields.cidr")}</label>
            <input
              type="text"
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
              placeholder={t("rules:placeholders.cidr")}
              className="w-full border border-slate-300 rounded-md px-2 py-1.5 text-sm font-mono"
              required
            />
          </div>
        )}

        {type === "ratelimit" && (
          <div>
            <label className="block text-sm mb-1">{t("rules:fields.pps")}</label>
            <input
              type="number"
              min={1}
              value={pps}
              onChange={(e) => setPps(e.target.value)}
              className="w-full border border-slate-300 rounded-md px-2 py-1.5 text-sm"
            />
          </div>
        )}

        {type === "syncookie" && (
          <div>
            <label className="block text-sm mb-1">{t("rules:fields.port")}</label>
            <input
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(e) => setPort(e.target.value)}
              className="w-full border border-slate-300 rounded-md px-2 py-1.5 text-sm"
              required
            />
          </div>
        )}

        <div>
          <label className="block text-sm mb-1">{t("rules:fields.ttl")}</label>
          <input
            type="number"
            min={1}
            max={2592000}
            value={ttl}
            onChange={(e) => setTtl(e.target.value)}
            className="w-full border border-slate-300 rounded-md px-2 py-1.5 text-sm"
            required
          />
        </div>
        {error && <div className="text-sm text-red-600">{error}</div>}
        <div className="flex gap-2">
          <Button type="submit" disabled={create.isPending}>
            {t("common:actions.submit")}
          </Button>
          <Button type="button" variant="secondary" onClick={() => navigate("/rules")}>
            {t("common:actions.cancel")}
          </Button>
        </div>
      </form>
    </div>
  );
}
