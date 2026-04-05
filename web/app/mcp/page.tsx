"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { API_URL } from "../lib/resqdCrypto";
import {
  fetchMe,
  loadMasterKey,
  bytesToB64u,
  type SessionUser,
} from "../lib/passkey";

/**
 * MCP integration page — the dedicated "let Claude drive your vault"
 * documentation. Lives inside the app shell so signed-in users find it
 * via their first tour of the nav, and linked from the landing page's
 * feature card so cold visitors can see the agent story before signup.
 *
 * The page hand-holds the three steps that turn a passkey-auth vault
 * into an LLM-accessible one: install the MCP binary, mint an API
 * token, copy the master key, paste everything into the client config.
 * The master key live-fills from sessionStorage if the user has one.
 */
export default function McpPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [masterKeyB64, setMasterKeyB64] = useState<string | null>(null);
  const [os, setOs] = useState<"mac" | "linux" | "win">("mac");

  useEffect(() => {
    (async () => {
      const me = await fetchMe();
      setUser(me); // not redirecting — page works for logged-out visitors too
      const mk = loadMasterKey();
      if (mk) setMasterKeyB64(bytesToB64u(mk));
    })();
    if (typeof navigator !== "undefined") {
      const ua = navigator.userAgent.toLowerCase();
      if (ua.includes("mac")) setOs("mac");
      else if (ua.includes("linux")) setOs("linux");
      else if (ua.includes("win")) setOs("win");
    }
  }, []);

  const copy = (text: string) => navigator.clipboard.writeText(text).catch(() => {});

  const desktopConfigPath =
    os === "mac"
      ? "~/Library/Application Support/Claude/claude_desktop_config.json"
      : os === "win"
        ? "%APPDATA%\\Claude\\claude_desktop_config.json"
        : "~/.config/Claude/claude_desktop_config.json";

  const desktopConfig = JSON.stringify(
    {
      mcpServers: {
        resqd: {
          command: "resqd-mcp",
          env: {
            RESQD_API_URL: API_URL,
            RESQD_API_TOKEN: "rsqd_your_token_here",
            RESQD_MASTER_KEY_B64: masterKeyB64 ?? "your_master_key_base64",
          },
        },
      },
    },
    null,
    2,
  );

  const claudeCodeCmd = `claude mcp add resqd resqd-mcp \\
  -e RESQD_API_URL=${API_URL} \\
  -e RESQD_API_TOKEN=rsqd_your_token_here \\
  -e RESQD_MASTER_KEY_B64=${masterKeyB64 ?? "your_master_key_base64"}`;

  return (
    <main className="min-h-screen bg-black text-slate-100">
      <nav className="sticky top-0 z-20 backdrop-blur bg-black/70 border-b border-slate-900">
        <div className="mx-auto max-w-4xl px-6 py-4 flex items-center justify-between">
          <Link href="/" className="font-bold tracking-tight text-lg">
            RESQD
          </Link>
          <div className="flex items-center gap-6 text-sm text-slate-400">
            {user ? (
              <Link href="/vault/" className="hover:text-slate-100">
                My vault
              </Link>
            ) : (
              <Link href="/signup/" className="hover:text-slate-100">
                Sign up
              </Link>
            )}
          </div>
        </div>
      </nav>

      <article className="mx-auto max-w-3xl px-6 py-12 text-slate-300">
        <header className="mb-12">
          <p className="text-xs uppercase tracking-widest text-amber-500 mb-3">
            MCP integration
          </p>
          <h1 className="text-4xl font-bold mb-4 text-slate-100">
            Let Claude drive your vault
          </h1>
          <p className="text-lg text-slate-400 leading-relaxed">
            RESQD ships a first-class{" "}
            <a
              href="https://modelcontextprotocol.io"
              className="text-amber-400 hover:underline"
            >
              Model Context Protocol
            </a>{" "}
            server so you can tell Claude things like{" "}
            <em>&ldquo;upload my tax return to my vault&rdquo;</em> or{" "}
            <em>&ldquo;list everything I saved last month&rdquo;</em>. The
            MCP server runs locally on your machine, encrypts your files
            with the same zero-knowledge stack as the browser, and
            authenticates to RESQD with a revocable API token. The server
            never sees plaintext.
          </p>
        </header>

        {!user && (
          <div className="mb-10 bg-amber-500/5 border border-amber-500/30 rounded-lg p-4 text-sm">
            <p className="text-amber-100">
              You&apos;ll need a RESQD account to generate an API token
              and use the MCP server.{" "}
              <Link
                href="/signup/"
                className="text-amber-400 hover:underline font-semibold"
              >
                Create a vault →
              </Link>
            </p>
          </div>
        )}

        <Section number="01" title="Install the MCP server">
          <p className="mb-4">
            <code className="bg-slate-900 px-1.5 py-0.5 rounded text-amber-300">
              resqd-mcp
            </code>{" "}
            is a small Rust binary that speaks MCP over stdio. Clone the
            repo and install with cargo (compiles in ~1 minute the first
            time):
          </p>
          <CodeBlock onCopy={copy}>
            {`git clone https://github.com/khiebel/resqd.git
cd resqd/mcp
cargo install --path .`}
          </CodeBlock>
          <p className="mt-4 text-sm text-slate-500">
            This puts{" "}
            <code className="text-amber-300">resqd-mcp</code> at{" "}
            <code className="text-amber-300">~/.cargo/bin/resqd-mcp</code>,
            which should already be on your <code>$PATH</code>.
          </p>
        </Section>

        <Section number="02" title="Mint an API token">
          <p className="mb-4">
            Tokens have the same permissions as your passkey session —
            read, write, delete — and can be revoked at any time. Each
            client gets its own.
          </p>
          {user ? (
            <Link
              href="/settings/"
              className="inline-block rounded-lg bg-amber-500 text-slate-900 font-semibold px-5 py-2.5 text-sm"
            >
              Go to Settings → Mint token
            </Link>
          ) : (
            <Link
              href="/signup/"
              className="inline-block rounded-lg bg-amber-500 text-slate-900 font-semibold px-5 py-2.5 text-sm"
            >
              Sign up first
            </Link>
          )}
          <p className="mt-4 text-sm text-slate-500">
            The token is shown once when you mint it. Copy it somewhere
            safe — we only store its SHA-256 hash and can never show
            you the raw value again.
          </p>
        </Section>

        <Section number="03" title="Copy your master key">
          <p className="mb-4">
            The MCP server needs your master key to encrypt files locally
            before upload and decrypt them after download. It&apos;s the
            same key your browser derives from your passkey via the
            WebAuthn PRF extension — no plaintext, no key ever leaves
            your control except into this specific client config.
          </p>
          {user && masterKeyB64 ? (
            <p className="text-sm">
              Your master key is loaded in this tab.{" "}
              <Link
                href="/settings/"
                className="text-amber-400 hover:underline"
              >
                Reveal and copy it from Settings →
              </Link>
            </p>
          ) : user ? (
            <p className="text-sm text-slate-500">
              Your master key isn&apos;t in this tab&apos;s memory. Sign in
              again via <Link href="/login/" className="text-amber-400 hover:underline">/login</Link> to
              re-derive it from your passkey, then come back here or go
              straight to{" "}
              <Link href="/settings/" className="text-amber-400 hover:underline">Settings</Link>.
            </p>
          ) : (
            <p className="text-sm text-slate-500">
              Sign in to see your master key.
            </p>
          )}
          <div className="mt-4 bg-red-950/30 border border-red-900/50 rounded-lg p-3 text-xs text-red-200">
            <b className="text-red-100">Treat it like a root password.</b>{" "}
            Anyone who holds your master key can decrypt everything in
            your vault. Put it in your MCP client&apos;s secret store;
            don&apos;t paste it into a shared shell history or commit it
            to a repo.
          </div>
        </Section>

        <Section number="04" title="Configure your MCP client">
          <div className="flex gap-2 mb-4">
            <OsTab current={os} value="mac" label="macOS" onClick={setOs} />
            <OsTab current={os} value="linux" label="Linux" onClick={setOs} />
            <OsTab current={os} value="win" label="Windows" onClick={setOs} />
          </div>

          <h3 className="text-slate-100 font-semibold mb-2">Claude Desktop</h3>
          <p className="text-sm mb-3">
            Edit{" "}
            <code className="bg-slate-900 px-1.5 py-0.5 rounded text-amber-300">
              {desktopConfigPath}
            </code>{" "}
            and add the <code>resqd</code> entry under{" "}
            <code>mcpServers</code>:
          </p>
          <CodeBlock onCopy={copy}>{desktopConfig}</CodeBlock>
          <p className="mt-3 text-sm text-slate-500">
            Restart Claude Desktop. You should see{" "}
            <code className="text-amber-300">resqd</code> in the MCP
            indicator with four tools available.
          </p>

          <h3 className="text-slate-100 font-semibold mt-8 mb-2">Claude Code</h3>
          <CodeBlock onCopy={copy}>{claudeCodeCmd}</CodeBlock>
          <p className="mt-3 text-sm text-slate-500">
            Then run <code className="text-amber-300">/mcp</code> inside
            Claude Code to verify the connection.
          </p>
        </Section>

        <Section number="05" title="Try it">
          <p className="mb-4">
            Once Claude has the server, try any of these prompts:
          </p>
          <ul className="space-y-2 text-sm italic text-slate-400 [&_li]:before:content-['\201C'] [&_li]:after:content-['\201D']">
            <li>Upload ~/Documents/tax_return_2026.pdf to my RESQD vault.</li>
            <li>List everything in my vault.</li>
            <li>Download asset 8e2f7c… to ~/Desktop/recovered.pdf.</li>
            <li>
              Delete the file called &ldquo;old_draft.txt&rdquo; from my
              vault.
            </li>
          </ul>
          <p className="mt-6 text-sm text-slate-500">
            Every upload is encrypted locally with a fresh per-asset key,
            sharded across six storage backends, and anchored on Base L2
            — byte-for-byte identical to what the browser upload flow
            writes. Anything you drop in via Claude shows up with its
            real filename in{" "}
            <Link href="/vault/" className="text-amber-400 hover:underline">
              your vault
            </Link>
            .
          </p>
        </Section>

        <Section number="06" title="Four tools">
          <ToolCard
            name="upload_file"
            args="{ path, name? }"
            body="Encrypt a file from disk and add it to your vault. Returns the new asset id."
          />
          <ToolCard
            name="list_vault"
            args="{}"
            body="List your vault's assets with decrypted filenames and MIME types. Filenames are decrypted locally — the server only returns ciphertext."
          />
          <ToolCard
            name="fetch_file"
            args="{ asset_id, save_to }"
            body="Download an asset, decrypt it locally, write it to a path. Triggers a canary rotation and on-chain anchor."
          />
          <ToolCard
            name="delete_file"
            args="{ asset_id }"
            body="Permanently remove an asset. On-chain canary history is preserved (Base is append-only by design)."
          />
        </Section>

        <Section number="07" title="Zero-knowledge caveat">
          <p className="leading-relaxed">
            The MCP server has a copy of your master key. That&apos;s how
            it can encrypt and decrypt locally without ever handing
            plaintext to the RESQD server. It&apos;s a real delegation —
            treat the machine running the MCP like one you&apos;d trust
            with your vault, because for the lifetime of that key copy,
            it has the same access you do.
          </p>
          <p className="mt-4 leading-relaxed">
            A future version will use proxy re-encryption so each agent
            holds only a delegated key scoped to specific assets, making
            the delegation revocable and narrow. For the alpha, the
            simpler shape ships so the integration is honestly useful
            while we iterate on the harder design.
          </p>
        </Section>
      </article>
    </main>
  );
}

function Section({
  number,
  title,
  children,
}: {
  number: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mb-12 pb-12 border-b border-slate-900 last:border-b-0">
      <div className="flex items-start gap-6">
        <div className="text-3xl font-mono bg-gradient-to-b from-amber-300 to-violet-500 bg-clip-text text-transparent shrink-0">
          {number}
        </div>
        <div className="flex-1">
          <h2 className="text-2xl font-bold mb-4 text-slate-100">{title}</h2>
          <div className="text-sm leading-relaxed">{children}</div>
        </div>
      </div>
    </section>
  );
}

function CodeBlock({
  children,
  onCopy,
}: {
  children: string;
  onCopy: (text: string) => void;
}) {
  return (
    <div className="relative bg-slate-950 border border-slate-800 rounded-lg">
      <pre className="p-4 pr-20 text-xs font-mono text-slate-200 overflow-x-auto whitespace-pre-wrap">
        {children}
      </pre>
      <button
        onClick={() => onCopy(children)}
        className="absolute top-2 right-2 text-xs text-amber-400 hover:text-amber-200 bg-slate-900 border border-slate-800 rounded px-2 py-1"
      >
        Copy
      </button>
    </div>
  );
}

function OsTab({
  current,
  value,
  label,
  onClick,
}: {
  current: string;
  value: "mac" | "linux" | "win";
  label: string;
  onClick: (v: "mac" | "linux" | "win") => void;
}) {
  const active = current === value;
  return (
    <button
      onClick={() => onClick(value)}
      className={`text-xs px-3 py-1.5 rounded-lg border ${
        active
          ? "bg-amber-500/10 border-amber-500/40 text-amber-200"
          : "border-slate-800 text-slate-400 hover:text-slate-200"
      }`}
    >
      {label}
    </button>
  );
}

function ToolCard({
  name,
  args,
  body,
}: {
  name: string;
  args: string;
  body: string;
}) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 mb-3">
      <div className="flex items-baseline gap-3 mb-1">
        <code className="text-amber-300 font-mono">{name}</code>
        <code className="text-xs text-slate-500 font-mono">{args}</code>
      </div>
      <p className="text-sm text-slate-400">{body}</p>
    </div>
  );
}
