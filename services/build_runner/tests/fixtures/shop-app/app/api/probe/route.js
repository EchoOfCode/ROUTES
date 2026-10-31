import { NextResponse } from "next/server";
import fs from "node:fs";
import net from "node:net";
import { pool } from "../../../lib/db";

export const dynamic = "force-dynamic";

// Fixture-only: the application inspects its own sandbox and reports what it can
// reach. ROUTES' test plan asserts that every forbidden path is closed.

function tcp(host, port, timeout = 1500) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const done = (state) => { socket.destroy(); resolve(state); };
    socket.setTimeout(timeout, () => done("timeout"));
    socket.once("connect", () => done("connected"));
    socket.once("error", (e) => done(e.code || "error"));
  });
}

function unixSocket(path) {
  return new Promise((resolve) => {
    if (!fs.existsSync(path)) return resolve("absent");
    const socket = net.connect({ path });
    socket.once("connect", () => { socket.destroy(); resolve("connected"); });
    socket.once("error", (e) => resolve(e.code || "error"));
  });
}

function read(path) {
  try { return fs.readFileSync(path, "utf8").trim(); } catch { return null; }
}

export async function GET() {
  const targets = {
    metadata: ["169.254.169.254", 80],
    internet_https: ["1.1.1.1", 443],
    internet_dns: ["8.8.8.8", 53],
    registry: ["registry.npmjs.org", 443],
    host_alias_web: ["host.docker.internal", 80],
    host_alias_docker: ["host.docker.internal", 2375],
    gateway: ["routes-p1-gateway", 3128],
    sandbox_manager: ["sandbox-manager", 8100],
    docker_proxy: ["docker-proxy", 2375],
    web_postgres: ["postgres", 5432],
  };
  const network = {};
  for (const [name, [host, port]] of Object.entries(targets)) network[name] = await tcp(host, port);

  let rootWritable = false;
  try { fs.writeFileSync("/etc/routes-probe", "x"); rootWritable = true; } catch {}

  let dbOk = false;
  try { await pool.query("SELECT count(*) FROM products"); dbOk = true; } catch {}

  const mounts = (read("/proc/self/mountinfo") || "").split("\n").map((l) => {
    const [pre, post] = l.split(" - ");
    const f = (pre || "").split(" ");
    return { mountpoint: f[4], fstype: (post || "").split(" ")[0] };
  });
  const hostMounts = mounts.filter((m) => !["tmpfs", "proc", "sysfs", "cgroup2", "cgroup", "devpts", "mqueue",
    "overlay", "shm", "devtmpfs"].includes(m.fstype) && !["/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/input"].includes(m.mountpoint));

  const env = Object.entries(process.env);
  return NextResponse.json({
    uid: process.getuid(),
    running_as_root: process.getuid() === 0,
    docker_socket: (await unixSocket("/var/run/docker.sock")) === "connected",
    docker_socket_state: await unixSocket("/var/run/docker.sock"),
    root_fs_writable: rootWritable,
    host_mounts: hostMounts.map((m) => `${m.mountpoint} (${m.fstype})`),
    has_host_mounts: hostMounts.length > 0,
    network,
    any_forbidden_reachable: Object.values(network).includes("connected"),
    db_ok: dbOk,
    database_host: process.env.PGHOST || null,
    postinstall_ran: fs.existsSync(process.cwd() + "/.postinstall-ran"),
    credentials_in_env: env.some(([k, v]) => /GITHUB|GH_TOKEN|ROUTES_PROXY/.test(k) || /ghp_|github_pat_/.test(v || "")),
    limits: {
      memory_max: read("/sys/fs/cgroup/memory.max"),
      pids_max: read("/sys/fs/cgroup/pids.max"),
      cpu_max: read("/sys/fs/cgroup/cpu.max"),
    },
  });
}
