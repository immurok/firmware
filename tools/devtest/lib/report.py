"""报告：Markdown 给人看，JSON 给下次比对。"""
import json
import os

ICON = {"PASS": "✅", "FAIL": "❌", "SKIP": "⏭", "INVALID": "⚠️"}


def write(dir, started, records, env, transcript):
    os.makedirs(dir, exist_ok=True)
    base = os.path.join(dir, started)
    with open(base + ".json", "w") as f:
        json.dump({"started": started, "env": env, "records": records,
                   "transcript": transcript}, f, ensure_ascii=False, indent=1)
    counts = {k: sum(1 for r in records if r["status"] == k) for k in ICON}
    lines = [f"# devtest 报告 {started}", "",
             f"环境：`{json.dumps(env, ensure_ascii=False)}`", "",
             "| 状态 | 数 |", "|---|---|"]
    lines += [f"| {ICON[k]} {k} | {v} |" for k, v in counts.items()]
    lines += ["", "## 汇总", "", "| ID | 用例 | 状态 | 耗时 | 备注 |", "|---|---|---|---|---|"]
    for r in records:
        note = r["note"].replace("\n", " ").replace("|", "/")
        lines.append(f"| {r['id']} | {r['title']} | {ICON[r['status']]} {r['status']} | "
                     f"{r['seconds']:.1f}s | {note} |")
    bad = [r for r in records if r["status"] in ("FAIL", "INVALID")]
    if bad:
        lines += ["", "## 需要看的", ""]
        for r in bad:
            lines += [f"### {r['id']} {r['title']} — {r['status']}", "", r["note"], ""]
            if r["health_diff"]:
                lines += ["体检 diff：", ""] + [f"- {d}" for d in r["health_diff"]] + [""]
            if r["uart_reset"]:
                lines += [f"设备日志出现复位字样：`{r['uart_reset']}`", ""]
            if r["evidence"]:
                lines += ["```json", json.dumps(r["evidence"], ensure_ascii=False, indent=1), "```", ""]
            if r["log"]:
                lines += ["```", *r["log"], "```", ""]
            if r["bus"]:
                lines += ["事件总线：", "```", *r["bus"][-40:], "```", ""]
            if r["uart"]:
                lines += ["设备日志：", "```", r["uart"][-3000:], "```", ""]
    if transcript:
        lines += ["", "## 操作员交互", ""] + [f"- {t} `{p}` → {a}" for t, p, a in transcript]
    with open(base + ".md", "w") as f:
        f.write("\n".join(lines) + "\n")
    return base + ".md", base + ".json"
