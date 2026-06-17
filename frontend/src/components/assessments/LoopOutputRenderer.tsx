import type { LoopRun } from "../../api/assessments";
import { VulnProfileView } from "./VulnProfileView";
import { IndicatorTable } from "./IndicatorTable";
import { RuleList } from "./RuleList";

interface Props {
  loopNumber: 1 | 2 | 3;
  output: LoopRun["output"];
  lowDetectabilityOverride?: boolean;
}

export function LoopOutputRenderer({ loopNumber, output, lowDetectabilityOverride }: Props) {
  if (loopNumber === 1) {
    return <VulnProfileView output={output as never} />;
  }
  if (loopNumber === 2) {
    return <IndicatorTable output={output as never} />;
  }
  return (
    <RuleList
      output={output as never}
      lowDetectabilityOverride={lowDetectabilityOverride ?? false}
    />
  );
}
