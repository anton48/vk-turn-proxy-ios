# Patched fork of wireguard-go

Copy of `golang.zx2c4.com/wireguard@v0.0.0-20250521234502-f333402bd9cb`, vendored
here (via `replace` in both go.mod files) so it can be patched for vk-turn-proxy's
**flow-local path set**. Upstream LICENSE/COPYING are unchanged (MIT).

We do not track upstream — do not blindly update this. Our patch (search
`vk-turn-proxy` / `flowKey`):

- `device/send.go`: `QueueOutboundElement.flowKey`; hash the inner 5-tuple in
  `RoutineReadFromTUN` (where the packet is still plaintext); thread it through
  `RoutineSequentialSender` → `Peer.SendBuffers`.
- `device/flowkey.go` (new): `flowKeyOf` (FNV-1a over the 5-tuple, 0 = unknown).
- `device/peer.go`: `SendBuffers(bufs, flowKeys)` routes to `conn.FlowSender` when
  the bind implements it, else the plain `Send`.
- `conn/conn.go`: optional `FlowSender` interface (does not touch `conn.Bind`, so
  the stock binds compile unchanged).

Our `TURNBind` (pkg/turnbind) implements `FlowSender`; the proxy consumes the key
in `SendPacketFlow`. PR1 only carries+accounts the key (memstats `flowkey=N/M`);
dispatch by it is PR2.
