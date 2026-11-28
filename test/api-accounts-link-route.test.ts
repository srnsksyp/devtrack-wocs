import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { POST } from "@/app/api/accounts/link/route";
import { getServerSession } from "@/lib/server-session";
import { authOptions } from "@/lib/auth";

vi.mock("@/lib/server-session", () => ({
  getServerSession: vi.fn(),
}));

vi.mock("@/lib/auth", () => ({
  authOptions: {},
}));

describe("POST /api/accounts/link", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env = {
      ...originalEnv,
      NEXTAUTH_URL: "https://devtrack.example.com",
      GITHUB_ID: "test-client-id",
      NODE_ENV: "test",
    };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("Authentication", () => {
    it("returns 401 when there is no session", async () => {
      vi.mocked(getServerSession).mockResolvedValue(null);

      const res = await POST();

      expect(res.status).toBe(401);
      expect(getServerSession).toHaveBeenCalledWith(authOptions);

      const body = await res.json();
      expect(body).toEqual({ error: "Must be signed in to link an account" });
    });

    it("returns 401 when session has no githubId", async () => {
      vi.mocked(getServerSession).mockResolvedValue({
        user: { name: "Test User" },
      } as never);

      const res = await POST();

      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body).toEqual({ error: "Must be signed in to link an account" });
    });
  });

  describe("OAuth URL generation and CSRF state", () => {
    it("returns the GitHub OAuth authorization URL and sets CSRF cookie on success", async () => {
      vi.mocked(getServerSession).mockResolvedValue({
        githubId: "gh-12345",
        githubLogin: "octocat",
      } as never);

      const res = await POST();

      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body).toHaveProperty("url");

      const parsedUrl = new URL(body.url);
      expect(parsedUrl.origin).toBe("https://github.com");
      expect(parsedUrl.pathname).toBe("/login/oauth/authorize");
      expect(parsedUrl.searchParams.get("client_id")).toBe("test-client-id");
      expect(parsedUrl.searchParams.get("redirect_uri")).toBe(
        "https://devtrack.example.com/api/auth/link-github/callback"
      );
      expect(parsedUrl.searchParams.get("scope")).toBe("read:user");

      const stateParam = parsedUrl.searchParams.get("state");
      expect(stateParam).toBeTruthy();
      expect(stateParam).toMatch(/^[a-f0-9]{64}\.gh-12345$/);

      // Verify the CSRF state cookie is set
      const stateCookie = res.cookies.get("link_github_state");
      expect(stateCookie).toBeDefined();
      expect(stateCookie?.value).toBe(stateParam);
      expect(stateCookie?.httpOnly).toBe(true);
      expect(stateCookie?.sameSite).toBe("lax");
      expect(stateCookie?.path).toBe("/");
      expect(stateCookie?.maxAge).toBe(600);
      expect(stateCookie?.secure).toBe(false);
    });

    it("sets secure cookie flag in production environment", async () => {
      vi.stubEnv("NODE_ENV", "production");
      vi.mocked(getServerSession).mockResolvedValue({
        githubId: "gh-67890",
        githubLogin: "alice",
      } as never);

      const res = await POST();

      expect(res.status).toBe(200);
      const stateCookie = res.cookies.get("link_github_state");
      expect(stateCookie).toBeDefined();
      expect(stateCookie?.secure).toBe(true);
      vi.unstubAllEnvs();
    });

    it("handles missing NEXTAUTH_URL and GITHUB_ID environment variables gracefully", async () => {
      delete process.env.NEXTAUTH_URL;
      delete process.env.GITHUB_ID;

      vi.mocked(getServerSession).mockResolvedValue({
        githubId: "gh-fallback-user",
      } as never);

      const res = await POST();

      expect(res.status).toBe(200);
      const body = await res.json();
      const parsedUrl = new URL(body.url);

      expect(parsedUrl.searchParams.get("client_id")).toBe("");
      expect(parsedUrl.searchParams.get("redirect_uri")).toBe(
        "/api/auth/link-github/callback"
      );
      expect(parsedUrl.searchParams.get("state")).toMatch(
        /^[a-f0-9]{64}\.gh-fallback-user$/
      );
    });

    it("generates a unique state nonce on every request", async () => {
      vi.mocked(getServerSession).mockResolvedValue({
        githubId: "gh-unique",
      } as never);

      const res1 = await POST();
      const res2 = await POST();

      const body1 = await res1.json();
      const body2 = await res2.json();

      const state1 = new URL(body1.url).searchParams.get("state");
      const state2 = new URL(body2.url).searchParams.get("state");

      expect(state1).not.toBe(state2);
      expect(res1.cookies.get("link_github_state")?.value).toBe(state1);
      expect(res2.cookies.get("link_github_state")?.value).toBe(state2);
    });
  });
});
