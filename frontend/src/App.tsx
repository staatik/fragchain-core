import { Navigate, Route, Routes } from "react-router-dom";
import { ProtectedLayout } from "./components/Layout";
import { Login } from "./screens/Login";
import { Identity } from "./screens/Identity";
import { CVEExplorer } from "./screens/CVEExplorer";
import { ChainsList } from "./screens/ChainsList";
import { ChainViewer } from "./screens/ChainViewer";
import { ManualCveAdd } from "./screens/ManualCveAdd";
import { ATTACKMatrix } from "./screens/ATTACKMatrix";
import { Dashboard } from "./screens/Dashboard";
import { ImportManager } from "./screens/ImportManager";
import { SigmaLibrary } from "./screens/SigmaLibrary";
import { ReviewQueue } from "./screens/ReviewQueue";
import { Prompts } from "./screens/Prompts";
import { Settings } from "./screens/Settings";
import AssessmentsList from "./screens/AssessmentsList";
import AssessmentWorkspace from "./screens/AssessmentWorkspace";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />

      {/* ChainViewer / Matrix / ReviewQueue render their own AppShell so
          they can drive the context-bar actions (CVE id, confidence,
          queue navigation). We mount them outside ProtectedLayout but
          still guard auth via the same axios interceptor — a 401 punts
          to /login. */}
      <Route element={<ProtectedLayout chromeless />}>
        <Route path="/chains/:cve_id" element={<ChainViewer />} />
        <Route path="/matrix" element={<ATTACKMatrix />} />
        <Route path="/queue" element={<ReviewQueue />} />
        <Route path="/assessments" element={<AssessmentsList />} />
        <Route path="/assessments/:id" element={<AssessmentWorkspace />} />
      </Route>

      <Route element={<ProtectedLayout />}>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/cves" element={<CVEExplorer />} />
        <Route path="/cves/new" element={<ManualCveAdd />} />
        <Route path="/chains" element={<ChainsList />} />
        <Route path="/rules" element={<SigmaLibrary />} />
        <Route path="/imports" element={<ImportManager />} />
        <Route path="/prompts" element={<Prompts />} />
        <Route path="/settings/*" element={<Settings />} />
        <Route path="/identity" element={<Identity />} />
      </Route>

      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
