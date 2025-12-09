import { router } from "../trpc";
import { authRouter } from "./auth";
import { accountRouter } from "./account";

export const appRouter = router({
  auth: authRouter,
  account: accountRouter,
});

export type AppRouter = typeof appRouter;
