import { Navigate, Route, Routes } from "react-router-dom";

import { SettingsLayout } from "./settings/SettingsLayout";
import { CommonsSection } from "./settings/CommonsSection";
import { ConnectorsSection } from "./settings/ConnectorsSection";
import { LimitsSection } from "./settings/LimitsSection";
import { NotificationsSection } from "./settings/NotificationsSection";
import { ProfilesSection } from "./settings/ProfilesSection";
import { ProvidersSection } from "./settings/ProvidersSection";
import { SigmaSourcesSection } from "./settings/SigmaSourcesSection";
import { SigmaTargetsSection } from "./settings/SigmaTargetsSection";

/** Settings + Marketplace + system configuration shell (M24).
 *
 *  Mounted at `/settings/*`. The left sub-nav (rendered by SettingsLayout)
 *  switches between sections. Each section owns its own data fetching,
 *  modal/form state, and toast announcements. Default landing is the
 *  Connectors section, which the sidebar's main "Connectors" link also
 *  resolves to.
 */
export function Settings() {
  return (
    <SettingsLayout>
      <Routes>
        <Route index element={<Navigate to="connectors" replace />} />
        <Route path="connectors" element={<ConnectorsSection />} />
        <Route path="commons" element={<CommonsSection />} />
        <Route path="sigma-sources" element={<SigmaSourcesSection />} />
        <Route path="sigma-targets" element={<SigmaTargetsSection />} />
        <Route path="profiles" element={<ProfilesSection />} />
        <Route path="limits" element={<LimitsSection />} />
        <Route path="notifications" element={<NotificationsSection />} />
        <Route path="providers" element={<ProvidersSection />} />
        <Route path="*" element={<Navigate to="connectors" replace />} />
      </Routes>
    </SettingsLayout>
  );
}
