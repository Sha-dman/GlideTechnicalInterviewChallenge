import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../trpc";
import { db } from "@/lib/db";
import { accounts, transactions } from "@/lib/db/schema";
import { eq, and, sql } from "drizzle-orm";
import { desc } from "drizzle-orm";
import crypto from "crypto";

// Generates a 10-digit secure random account number
function generateAccountNumber(): string {
  let accountNumber = "";
  while (accountNumber.length < 10) {
    const randomBytes = crypto.randomBytes(5); // 5 bytes = 40 bits
    const num = parseInt(randomBytes.toString("hex"), 16);
    accountNumber += num.toString().slice(0, 10 - accountNumber.length);
  }
  return accountNumber;
}


export const accountRouter = router({
  createAccount: protectedProcedure
    .input(
      z.object({
        accountType: z.enum(["checking", "savings"]),
      })
    )
    .mutation(async ({ input, ctx }) => {
      // Check if user already has an account of this type
      const existingAccount = await db
        .select()
        .from(accounts)
        .where(and(eq(accounts.userId, ctx.user.id), eq(accounts.accountType, input.accountType)))
        .get();

      if (existingAccount) {
        throw new TRPCError({
          code: "CONFLICT",
          message: `You already have a ${input.accountType} account`,
        });
      }

      let accountNumber;
      let isUnique = false;

      // Generate unique account number
      while (!isUnique) {
        accountNumber = generateAccountNumber();
        const existing = await db.select().from(accounts).where(eq(accounts.accountNumber, accountNumber)).get();
        isUnique = !existing;
      }

      await db.insert(accounts).values({
        userId: ctx.user.id,
        accountNumber: accountNumber!,
        accountType: input.accountType,
        balance: 0,
        status: "active",
      });

      // Fetch the created account
      const account = await db.select().from(accounts).where(eq(accounts.accountNumber, accountNumber!)).get();

      return (
        account || {
          id: 0,
          userId: ctx.user.id,
          accountNumber: accountNumber!,
          accountType: input.accountType,
          balance: 0, // previously 100, user should not have anything to start with
          status: "pending",
          createdAt: new Date().toISOString(),
        }
      );
    }),

  getAccounts: protectedProcedure.query(async ({ ctx }) => {
    const userAccounts = await db.select().from(accounts).where(eq(accounts.userId, ctx.user.id));

    return userAccounts;
  }),

  fundAccount: protectedProcedure
  .input(
    z.object({
      accountId: z.number(),
      amount: z.number().positive(),
      fundingSource: z.object({
        type: z.enum(["card", "bank"]),
        accountNumber: z.string(),
        routingNumber: z.string().optional(),
      }),
    })
  )
  .mutation(async ({ input, ctx }) => {
    const amount = parseFloat(input.amount.toString());

    // Verify account belongs to user
    const account = await db
      .select()
      .from(accounts)
      .where(and(eq(accounts.id, input.accountId), eq(accounts.userId, ctx.user.id)))
      .get();

    if (!account) {
      throw new TRPCError({
        code: "NOT_FOUND",
        message: "Account not found",
      });
    }

    if (account.status !== "active") {
      throw new TRPCError({
        code: "BAD_REQUEST",
        message: "Account is not active",
      });
    }
    // 206
    function isValidCardNumber(cardNumber: string): boolean {
      const digits = cardNumber.replace(/\D/g, "");
      let sum = 0;
      let shouldDouble = false;
    
      for (let i = digits.length - 1; i >= 0; i--) {
        let digit = parseInt(digits[i], 10);
        if (shouldDouble) {
          digit *= 2;
          if (digit > 9) digit -= 9;
        }
        sum += digit;
        shouldDouble = !shouldDouble;
      }
    
      return sum % 10 === 0;
    }
    
    if (input.fundingSource.type === "card" && !isValidCardNumber(input.fundingSource.accountNumber)) {
      throw new TRPCError({ code: "BAD_REQUEST", message: "Invalid card number" });
    }
    // Create transaction
    const [transactionId] = await db
      .insert(transactions)
      .values({
        accountId: input.accountId,
        type: "deposit",
        amount,
        description: `Funding from ${input.fundingSource.type}`,
        status: "completed",
        processedAt: new Date().toISOString(),
      })
      .returning({ id: transactions.id });

    // Atomically update account balance
    await db
      .update(accounts)
      .set({
        balance: sql`${accounts.balance} + ${amount}`, // add full amount safely
      })
      .where(eq(accounts.id, input.accountId));

    // Fetch updated account balance
    const updatedAccount = await db
      .select()
      .from(accounts)
      .where(eq(accounts.id, input.accountId))
      .get();

    return {
      transactionId,
      newBalance: updatedAccount?.balance ?? account.balance,
    };
  }),

  getTransactions: protectedProcedure
    .input(
      z.object({
        accountId: z.number(),
      })
    )
    .query(async ({ input, ctx }) => {
      // Verify account belongs to user
      const account = await db
        .select()
        .from(accounts)
        .where(and(eq(accounts.id, input.accountId), eq(accounts.userId, ctx.user.id)))
        .get();

      if (!account) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Account not found",
        });
      }

      // const accountTransactions = await db
      //   .select()
      //   .from(transactions)
      //   .where(eq(transactions.accountId, input.accountId))
      //   .orderBy(desc(transactions.createdAt), desc(transactions.id)) // added to sort by newest first
      const accountTransactions = await db
      .select({
        id: transactions.id,
        accountId: transactions.accountId,
        type: transactions.type,
        amount: transactions.amount,
        description: transactions.description,
        status: transactions.status,
        createdAt: transactions.createdAt,
        processedAt: transactions.processedAt,
        accountType: accounts.accountType, // joined field
      })
      .from(transactions)
      .leftJoin(accounts, eq(transactions.accountId, accounts.id))
      .where(eq(transactions.accountId, input.accountId))
      .orderBy(desc(transactions.createdAt), desc(transactions.id));

      const enrichedTransactions = [];
      for (const transaction of accountTransactions) {
        const accountDetails = await db.select().from(accounts).where(eq(accounts.id, transaction.accountId)).get();

        enrichedTransactions.push({
          ...transaction,
          accountType: accountDetails?.accountType,
        });
      }

      return enrichedTransactions;
    }),
});
