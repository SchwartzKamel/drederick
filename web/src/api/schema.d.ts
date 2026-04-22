/**
 * Placeholder OpenAPI schema. Phase 2 agents will regenerate this from
 * the live backend using `pnpm generate:api`. Only `/api/health` is
 * modeled here to unblock the scaffold.
 */
export interface paths {
  "/api/health": {
    get: {
      responses: {
        200: {
          content: {
            "application/json": {
              status: string;
            };
          };
        };
      };
    };
  };
}
