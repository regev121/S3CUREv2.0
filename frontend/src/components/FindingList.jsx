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
                <summary className="text-light">
                  {evidence.every((grant) => grant.conditional) && "Potential · "}{title}
                </summary>
                <ul className="list-unstyled d-grid gap-2 mt-2 mb-0">
                  {evidence.map((grant, row) => (
                    <li key={row} className="border-top border-secondary pt-2 text-break">
                      <strong>{grant.policy}</strong>
                      <div className="text-body-secondary">
                        {[
                          grant.bucket && "Anonymous access · Bucket " + grant.bucket,
                          grant.direct && "Direct",
                          ...grant.groups.map((group) => "Group " + group),
                          grant.conditional && "Request conditions unresolved",
                        ]
                          .filter(Boolean).join(" · ")}
                      </div>
                      <code>{grant.action}</code> on <code>{grant.resource}</code>
                      {grant.matched_action && (
                        <div className="text-body-secondary">
                          Matched <code>{grant.matched_action}</code> on <code>{grant.matched_resource}</code>
                        </div>
                      )}
                      {grant.excluded_actions?.length > 0 && (
                        <div>Excluded actions <code>{grant.excluded_actions.join(", ")}</code></div>
                      )}
                      {grant.excluded_resources?.length > 0 && (
                        <div>Excluded resources <code>{grant.excluded_resources.join(", ")}</code></div>
                      )}
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
