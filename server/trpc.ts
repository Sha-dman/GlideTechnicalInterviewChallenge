import { initTRPC, TRPCError } from "@trpc/server";
import { CreateNextContextOptions } from "@trpc/server/adapters/next";
import { FetchCreateContextFnOptions } from "@trpc/server/adapters/fetch";
import jwt from "jsonwebtoken";
import { db } from "@/lib/db";
import { sessions, users } from "@/lib/db/schema";
import { eq } from "drizzle-orm";

export async function createContext(opts: CreateNextContextOptions | FetchCreateContextFnOptions) {
  let req: any;
  let res: any;

  if ("req" in opts && "res" in opts) {
    req = opts.req;
    res = opts.res;
  } else {
    req = opts.req;
    res = opts.resHeaders;
  }

  let token: string | undefined;

  let cookieHeader = "";
  if (req.headers.cookie) {
    cookieHeader = req.headers.cookie;
  } else if (req.headers.get) {
    cookieHeader = req.headers.get("cookie") || "";
  }

  const cookiesObj = Object.fromEntries(
    cookieHeader
      .split("; ")
      .filter(Boolean)
      .map((c: string) => {
        const [key, ...val] = c.split("=");
        return [key, val.join("=")];
      })
  );
  token = cookiesObj.session;

  let user = null;
  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || "temporary-secret-for-interview") as {
        userId: number;
      };

      const session = await db.select().from(sessions).where(eq(sessions.token, token)).get();

      if (session) {
        const now = Date.now();
        const expiresAtMs = new Date(session.expiresAt).getTime();

        const earlyExpiryWindow = 60_000; // 1 minute

        // Early expiration fix (PERF-403)
        if (expiresAtMs - now <= earlyExpiryWindow) {
          await db.delete(sessions).where(eq(sessions.token, token));
          throw new TRPCError({ code: "UNAUTHORIZED", message: "Session expired" });
        }

        // Valid session
        if (expiresAtMs > now) {
          user = await db.select().from(users).where(eq(users.id, decoded.userId)).get();
        }
      }
    } catch (error) {
      // Invalid session → ignore
    }
  }

  return {
    user,
    req,
    res,
  };
}

export type Context = Awaited<ReturnType<typeof createContext>>;

const t = initTRPC.context<Context>().create();

export const router = t.router;
export const publicProcedure = t.procedure;
export const protectedProcedure = t.procedure.use(async ({ ctx, next }) => {
  if (!ctx.user) {
    throw new TRPCError({ code: "UNAUTHORIZED" });
  }

  return next({
    ctx: {
      ...ctx,
      user: ctx.user,
    },
  });
});
