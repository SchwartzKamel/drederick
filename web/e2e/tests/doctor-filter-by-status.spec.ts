import { test } from "@playwright/test";

test("doctor: filter by warn status shows only warn rows", async ({ page }) => {
  test.fixme(
    true,
    "Requires a populated /api/doctor payload with mixed status rows. The " +
      "test webServer hasn't run `drederick doctor` so the endpoint returns " +
      "empty/seed data with no warn entries. Revisit when a test-seed path " +
      "lands (src/Drederick.Web/Endpoints/DoctorEndpoints.cs) or we mock " +
      "via page.route.",
  );
});
