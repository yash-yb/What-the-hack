"use client";

import { useState } from "react";
import { login } from "@/lib/api";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const result = await login(username, password);
      console.log("Logged in:", result);
      // later: redirect to /dashboard here
    } catch {
      setError("Login failed. Try again.");
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-100">
      <form
        onSubmit={handleSubmit}
        className="w-80 rounded-lg bg-white p-8 shadow-md"
      >
        <h1 className="mb-6 text-xl font-bold text-gray-800">
          Attack Forecasting — Login
        </h1>

        <label className="mb-1 block text-sm text-gray-600">Username</label>
        <input
          className="mb-4 w-full rounded border border-gray-300 p-2"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />

        <label className="mb-1 block text-sm text-gray-600">Password</label>
        <input
          type="password"
          className="mb-4 w-full rounded border border-gray-300 p-2"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        {error && <p className="mb-4 text-sm text-risk-high">{error}</p>}

        <button
          type="submit"
          className="w-full rounded bg-blue-600 py-2 text-white hover:bg-blue-700"
        >
          Log in
        </button>
      </form>
    </div>
  );
}