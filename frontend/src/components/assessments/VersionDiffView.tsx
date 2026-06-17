import { useState } from "react";
import { Modal } from "../Modal";
import { Dropdown } from "../Dropdown";
import type { DropdownOption } from "../Dropdown";
import type { LoopRun } from "../../api/assessments";

interface Props {
  loopNumber: 1 | 2 | 3;
  versions: LoopRun[];   // ordered version DESC
  onClose: () => void;
}

export function VersionDiffView({ loopNumber, versions, onClose }: Props) {
  const [leftId, setLeftId] = useState(versions[1]?.id ?? versions[0]?.id);
  const [rightId, setRightId] = useState(versions[0]?.id);

  const left = versions.find((v) => v.id === leftId) ?? versions[0];
  const right = versions.find((v) => v.id === rightId) ?? versions[0];

  const options: DropdownOption[] = versions.map((v) => ({
    value: v.id,
    label: `v${v.version}`,
  }));

  const preStyle: React.CSSProperties = {
    whiteSpace: "pre-wrap",
    background: "var(--surface3)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius-md)",
    padding: "var(--space-3)",
    fontFamily: "var(--font-display)",
    fontSize: "var(--text-xs)",
    margin: 0,
    overflowX: "auto",
  };

  return (
    <Modal open onClose={onClose} title={`Compare Loop ${loopNumber} versions`}>
      <div style={{ display: "flex", gap: "var(--space-2)", marginBottom: "var(--space-3)" }}>
        <Dropdown
          ariaLabel="Older version"
          options={options}
          value={leftId ?? null}
          onChange={(id) => id && setLeftId(id)}
        />
        <Dropdown
          ariaLabel="Newer version"
          options={options}
          value={rightId ?? null}
          onChange={(id) => id && setRightId(id)}
        />
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "var(--space-3)" }}>
        <pre style={preStyle}>
          {JSON.stringify(left.output, null, 2)}
        </pre>
        <pre style={preStyle}>
          {JSON.stringify(right.output, null, 2)}
        </pre>
      </div>
    </Modal>
  );
}
