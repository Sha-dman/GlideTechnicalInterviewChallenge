import { z } from "zod";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { TRPCError } from "@trpc/server";
import { publicProcedure, router } from "../trpc";
import { db } from "@/lib/db";
import { users, sessions } from "@/lib/db/schema";
import { eq } from "drizzle-orm";

// List of valid US state codes
const validStates = [
  "AL","AK","AZ","AR","CA","CO","CT","DE","FL","GA","HI","ID","IL","IN",
  "IA","KS","KY","LA","ME","MD","MA","MI","MN","MS","MO","MT","NE","NV",
  "NH","NJ","NM","NY","NC","ND","OH","OK","OR","PA","RI","SC","SD","TN",
  "TX","UT","VT","VA","WA","WV","WI","WY"
];

export const authRouter = router({
  signup: publicProcedure
    .input(
      z.object({
        email: z.string().email().toLowerCase(),
        password: z.string()
  .min(8, "Password must be at least 8 characters")
  .refine((v) => /[A-Z]/.test(v), "Password must include at least one uppercase letter")
  .refine((v) => /[a-z]/.test(v), "Password must include at least one lowercase letter")
  .refine((v) => /\d/.test(v), "Password must include at least one number")
  .refine((v) => /[!@#$%^&*(),.?":{}|<>]/.test(v), "Password must include at least one special character")
  .refine((v) => !["password","12345678","qwerty","letmein"].includes(v.toLowerCase()), "Password is too common"),
        firstName: z.string().min(1),
        lastName: z.string().min(1),
        phoneNumber: z
          .string()
          .trim()
          .regex(/^\+?[1-9]\d{1,14}$/, "Invalid phone number. Must be in international format, e.g. +14155552671"),
        dateOfBirth: z
          .string()
          .refine((val) => {
            const dob = new Date(val);
            const today = new Date();
            if (dob > today) return false; // cannot be in the future
            const age = today.getFullYear() - dob.getFullYear();
            if (age < 18) return false; // must be at least 18
            return true;
          }, { message: "Invalid date of birth. Must be in the past and 18+" }),
        ssn: z.string().regex(/^\d{9}$/),
        address: z.string().min(1),
        city: z.string().min(1),
        state: z
          .string()
          .trim()
          .toUpperCase()
          .length(2)
          .refine((val) => validStates.includes(val), { message: "Invalid state code" }),
        zipCode: z.string().regex(/^\d{5}$/),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const existingUser = await db.select().from(users).where(eq(users.email, input.email)).get();

      if (existingUser) {
        throw new TRPCError({ code: "CONFLICT", message: "User already exists" });
      }

      const hashedPassword = await bcrypt.hash(input.password, 10);
      // 301 similiar ^
      const hashedSSN = await bcrypt.hash(input.ssn, 10);
      await db.insert(users).values({
        ...input,
        password: hashedPassword,
        ssn: hashedSSN,
      });
      const user = await db.select().from(users).where(eq(users.email, input.email)).get();

  

      if (!user) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to create user" });
      }

      // Create session
      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || "temporary-secret-for-interview", { expiresIn: "7d" });
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      await db.insert(sessions).values({ userId: user.id, token, expiresAt: expiresAt.toISOString() });

      if ("setHeader" in ctx.res) {
        ctx.res.setHeader("Set-Cookie", `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
      } else {
        (ctx.res as Headers).set("Set-Cookie", `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
      }

      return { user: { ...user, password: undefined }, token };
    }),

  login: publicProcedure
    .input(
      z.object({ email: z.string().email(), password: z.string() })
    )
    .mutation(async ({ input, ctx }) => {
      const user = await db.select().from(users).where(eq(users.email, input.email)).get();
      if (!user) throw new TRPCError({ code: "UNAUTHORIZED", message: "Invalid credentials" });

      const validPassword = await bcrypt.compare(input.password, user.password);
      if (!validPassword) throw new TRPCError({ code: "UNAUTHORIZED", message: "Invalid credentials" });


      await db.delete(sessions).where(eq(sessions.userId, user.id)); // 304, delete all prev active sessions

      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || "temporary-secret-for-interview", { expiresIn: "7d" });
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      await db.insert(sessions).values({ userId: user.id, token, expiresAt: expiresAt.toISOString() });

      if ("setHeader" in ctx.res) {
        ctx.res.setHeader("Set-Cookie", `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
      } else {
        (ctx.res as Headers).set("Set-Cookie", `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
      }

      return { user: { ...user, password: undefined }, token };
    }),

  logout: publicProcedure.mutation(async ({ ctx }) => {
    let token: string | undefined;

    if (ctx.user) {
      // Get session token from request
      if ("cookies" in ctx.req) token = (ctx.req as any).cookies.session;
      else {
        const cookieHeader = ctx.req.headers.get?.("cookie") || (ctx.req.headers as any).cookie;
        token = cookieHeader?.split("; ").find((c: string) => c.startsWith("session="))?.split("=")[1];
      }
        //check for sessions
      if (token) {
        const deleted = await db.delete(sessions).where(eq(sessions.token, token));
        
        if (!deleted) {
          if ("setHeader" in ctx.res) {
            ctx.res.setHeader("Set-Cookie", `session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
          } else {
            (ctx.res as Headers).set("Set-Cookie", `session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
          }
          return { success: false, message: "Session could not be deleted" };
        }
      }
    }

    // Always clear cookie
    if ("setHeader" in ctx.res) {
      ctx.res.setHeader("Set-Cookie", `session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
    } else {
      (ctx.res as Headers).set("Set-Cookie", `session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
    }

    return { success: true, message: ctx.user ? "Logged out successfully" : "No active session" };
  }),
});
