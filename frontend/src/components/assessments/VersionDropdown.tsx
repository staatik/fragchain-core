import type { LoopRun } from "../../api/assessments";
import { Dropdown } from "../Dropdown";
import type { DropdownOption } from "../Dropdown";

interface Props {
  versions: LoopRun[];   // ordered version DESC
  selectedId: string;
  onSelect: (id: string) => void;
}

export function VersionDropdown({ versions, selectedId, onSelect }: Props) {
  const options: DropdownOption[] = versions.map((v) => ({
    value: v.id,
    label: `v${v.version}${v.is_active ? " (active)" : ""} — ${v.status}`,
  }));

  return (
    <Dropdown
      className="version-dropdown"
      ariaLabel="Loop run version"
      options={options}
      value={selectedId}
      onChange={(id) => id && onSelect(id)}
    />
  );
}
