/**
 * Edge front for the scanner container.
 *
 * This Worker does as little as possible on purpose. Every decision that
 * matters -- what counts as exploited, what the verdict says, what gets
 * refused -- lives in the Python engine that the CLI also runs. Re-implementing
 * any of it here would create a second code path, and a hosted answer that
 * disagreed with the terminal answer would make the tool useless for the one
 * job it exists to do.
 *
 * So: route to the container, add nothing, decide nothing.
 */

import { Container } from "@cloudflare/containers";

export class Scanner extends Container {
  defaultPort = 8080;

  // The container downloads the CISA KEV catalogue on boot, so a cold start is
  // slow. Ten minutes keeps one warm through a burst of visitors arriving from
  // the same link without paying to idle overnight. Billing is per 10ms of
  // runtime, so this is the knob that trades cost against first-scan latency.
  sleepAfter = "10m";

  onStart() {
    console.log("scanner container up");
  }

  onStop(reason) {
    console.log("scanner container down:", reason?.exitCode ?? "");
  }

  onError(error) {
    console.error("scanner container error:", error);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // A liveness probe that does not wake the container. Waking it to answer
    // "are you alive" would bill us for every uptime check anyone points here.
    if (url.pathname === "/up") {
      return Response.json({ ok: true, edge: true });
    }

    if (url.pathname !== "/scan" && url.pathname !== "/health") {
      return Response.json({ error: "not found" }, { status: 404 });
    }

    // One container, addressed by a fixed name: the KEV cache lives in the
    // instance's own filesystem, so spreading requests across instances would
    // make each one re-download the feed. Traffic at this stage is nowhere near
    // needing more than one.
    const container = env.SCANNER.getByName("scanner");

    try {
      return await container.fetch(request);
    } catch (error) {
      console.error("container fetch failed:", error);
      // Mirror the engine's own rule: never let a failure look like a clean
      // result. A 503 that says so beats an empty 200 that does not.
      return Response.json(
        {
          error:
            "the scanner is not reachable right now, so we are refusing to " +
            "return a result rather than return an empty one. Try again, or " +
            "run it locally: pip install flagrante",
        },
        { status: 503 }
      );
    }
  },
};
