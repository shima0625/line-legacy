import { createClient, safeError } from "./common.mjs";

const to = String(process.env.LINE_CALL_TO ?? "").trim();
if (!/^u[0-9a-f]{32}$/i.test(to)) {
  throw new Error("LINE_CALL_TO must be a 33-character user MID");
}

try {
  const { client } = await createClient();
  const route = await client.call.acquireCallRoute({
    to,
    callType: "AUDIO",
    fromEnvInfo: { devname: "Windows" },
  });

  // LINE 3.7.1 expects acquireCallRoute to return exactly seven strings.
  // Keep the route token off logs; stdout is captured directly by legy_proxy.
  const callFlowType = route.callFlowType === "PLANET"
    ? "2"
    : route.callFlowType === "NEW"
    ? "1"
    : String(route.callFlowType ?? "2");
  const routeAddresses = String(route.voipAddress ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  // Modern PLANET does not accept the 2013 AmpKit SIP registration. Route the
  // old client to the local SIP gateway, which then creates the PLANET call.
  const useLocalGateway = process.env.LINE_LEGACY_CALL_GATEWAY !== "0";
  const legacyHost = useLocalGateway
    ? String(process.env.LINE_LEGACY_CALL_HOST ?? "127.0.0.1")
    : (routeAddresses[0] ?? "");
  const legacyPort = useLocalGateway
    ? String(process.env.LINE_LEGACY_CALL_PORT ?? "19000")
    : String(route.voipUdpPort ?? "");
  const legacyFlowType = useLocalGateway ? "1" : callFlowType;
  const values = [
    String(route.fromToken ?? ""),
    legacyHost,
    legacyPort,
    legacyFlowType,
    String(route.fromZone ?? ""),
    String(route.toZone ?? ""),
    route.fakeCall === true ? "true" : "false",
  ];
  if (!values[0] || !values[1] || !values[2]) {
    throw new Error("LINE returned an incomplete call route");
  }
  process.stdout.write(JSON.stringify({
    ok: true,
    values,
    meta: {
      callFlowType: String(route.callFlowType ?? ""),
      addressParts: routeAddresses.length,
      localGateway: useLocalGateway,
    },
  }));
} catch (error) {
  process.stdout.write(JSON.stringify({ ok: false, error: safeError(error) }));
  process.exitCode = 2;
}
