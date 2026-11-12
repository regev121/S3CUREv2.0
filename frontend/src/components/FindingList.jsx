import { ShieldAlert } from "lucide-react";

export default function FindingList({ findings, emptyText }) {
  if (!findings?.length) {
    return <p className="small text-body-secondary mb-0">{emptyText}</p>;
  }

  return (
    <ul className="list-unstyled d-flex flex-column gap-2 mb-0">
      {findings.map((finding, index) => {
        const title = typeof finding === "string" ? finding : finding.rule;
        const evidence = finding.evidence ?? [];
        return (
          <li key={index} className="p-2 rounded bg-dark border border-secondary small">
            {evidence.length ? (
              <details>
                <summary className="text-light">{title}</summary>
                <ul className="list-unstyled d-grid gap-2 mt-2 mb-0">
                  {evidence.map((grant, row) => (
                    <li key={row} className="border-top border-secondary pt-2 text-break">
                      <strong>{grant.policy}</strong>
                      <div className="text-body-secondary">
                        {[grant.direct && "Direct", ...grant.groups.map((group) => "Group " + group)]
                          .filter(Boolean).join(" · ")}
                        {grant.conditional && " · Conditional grant"}
                      </div>
                      <code>{grant.action}</code> on <code>{grant.resource}</code>
                    </li>
                  ))}
                </ul>
              </details>
            ) : (
              <span className="text-light">
                <ShieldAlert size={16} className="text-danger me-2" />{title}
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}
