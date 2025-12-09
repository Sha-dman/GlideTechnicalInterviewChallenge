"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { trpc } from "@/lib/trpc/client";
import Link from "next/link";

type LoginFormData = {
  email: string;
  password: string;
};

export default function LoginPage() {
  const router = useRouter();
  const [error, setError] = useState("");

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormData>();
  const loginMutation = trpc.auth.login.useMutation();

  const onSubmit = async (data: LoginFormData) => {
    try {
      setError("");
      await loginMutation.mutateAsync(data);
      router.push("/dashboard");
    } catch (err: any) {
      setError(err.message || "Invalid credentials");
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">Sign in to your account</h2>
        </div>

        <form className="mt-8 space-y-6" onSubmit={handleSubmit(onSubmit)}>
          <div className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                Email
              </label>
              <input
                {...register("email", {
                  required: "Email is required",
                  pattern: {
                    value: /^[^\s@]+@[^\s@]+\.[a-zA-Z]{2,}$/i,
                    message: "Enter a valid email",
                  },
                validate: (value) => {
                const commonTypos = [".con", ".cmo", ".cim", ".ocm"];
                const lower = value.toLowerCase();
                if (commonTypos.some(t => lower.endsWith(t))) {
                return "Did you mean .com?";
                  }
                  return true;
                    },
                  })}
                  type="email"
                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm p-2 border"/>

              {errors.email && <p className="mt-1 text-sm text-red-600">{errors.email.message}</p>}
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                Password
              </label>
              <input
                {...register("password", { required: "Password is required" })}
                type="password"
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm p-2 border"
              />
              {errors.password && <p className="mt-1 text-sm text-red-600">{errors.password.message}</p>}
            </div>
          </div>

          {error && (
            <div className="rounded-md bg-red-50 p-4">
              <p className="text-sm text-red-800">{error}</p>
            </div>
          )}

          <button
            type="submit"
            disabled={loginMutation.isPending}
            className="w-full px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
          >
            {loginMutation.isPending ? "Signing in..." : "Sign In"}
          </button>
        </form>

        <p className="text-center text-sm text-gray-600">
          Don't have an account?{" "}
          <Link href="/signup" className="font-medium text-blue-600 hover:text-blue-500">
            Create one
          </Link>
        </p>
      </div>
    </div>
  );
}
