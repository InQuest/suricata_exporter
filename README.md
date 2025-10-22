# Suricata Prometheus Exporter

This is a Prometheus Exporter for Suricata using `dump-counters` via the
[unix socket](https://suricata.readthedocs.io/en/suricata-6.0.0/unix-socket.html#interacting-via-unix-socket)
to query metrics.

## Usage

```bash
$ ./suricata_exporter -h
Usage of ./suricata_exporter:
  -suricata.socket-path string
        Path to the Suricata Command socket. (default "/var/run/suricata.socket")
  -version
        Output version information.
  -web.listen-address string
        Address to listen on (default ":9917")
  -quiet
        supress logging messages when suricata is not enabled
  -totals
        Export only the overall global total metrics instead of per-thread metrics. (default false)
```

To verify the exporter is working with your Suricata setup, use the
following command to view a subset of the capture metrics.

```bash
$ curl -s localhost:9917/metrics | grep kernel_packets_total
# HELP suricata_capture_kernel_packets_total
# TYPE suricata_capture_kernel_packets_total counter
suricata_capture_kernel_packets_total{thread="W#01-eth1"} 7744
suricata_capture_kernel_packets_total{thread="W#02-eth1"} 8435
suricata_capture_kernel_packets_total{thread="W#03-eth1"} 7564
suricata_capture_kernel_packets_total{thread="W#04-eth1"} 9747
```

You can now configure a [Prometheus server](https://prometheus.io/docs/prometheus/latest/getting_started/)
to scrape the Suricata exporter in regular intervals for later visualization
and analysis.

### New Metrics Examples

Explore decoder events to identify packet parsing issues:
```bash
$ curl -s localhost:9917/metrics | grep decoder_events_total
suricata_decoder_events_total{event="opt_pad_required",protocol="ipv4",thread="W#01-eth1"} 2
suricata_decoder_events_total{event="pkt_too_small",protocol="tcp",thread="W#01-eth1"} 0
```

Monitor application layer parsing errors:
```bash
$ curl -s localhost:9917/metrics | grep app_layer_errors_total
suricata_app_layer_errors_total{error_type="parser",protocol="http",thread="W#01-eth1"} 0
suricata_app_layer_errors_total{error_type="gap",protocol="tls",thread="W#01-eth1"} 0
```

Track new v8 protocols:
```bash
$ curl -s localhost:9917/metrics | grep 'app_layer_flows_total.*\(mdns\|doh2\|websocket\)'
suricata_app_layer_flows_total{app="mdns",thread="W#01-eth1"} 15
suricata_app_layer_flows_total{app="doh2",thread="W#02-eth1"} 3
suricata_app_layer_flows_total{app="websocket",thread="W#03-eth1"} 1
```

## Metrics

### Comprehensive Coverage

The exporter provides extensive metric coverage across all Suricata subsystems:

**Per-Thread Metrics** (with `thread` label):
- **Capture**: Kernel packets/drops, AF_PACKET statistics, poll results
- **Decoder**: Packet counts by protocol (IPv4, IPv6, TCP, UDP, VLAN, GRE, MPLS, etc.)
- **Decoder Events**: Packet parsing errors dynamically extracted for all protocols (248+ event types)
  - Example: `suricata_decoder_events_total{protocol="ipv4",event="opt_pad_required",thread="W#01"}`
- **Flow**: Flow tracking, active flows, flow end states (new, established, closed, bypassed)
- **TCP**: Sessions, reassembly, stream depth, segment handling
- **Defrag**: IPv4/IPv6 fragmentation and reassembly statistics
- **App Layer**: Protocol flows dynamically extracted (HTTP, TLS, DNS, SSH, SMTP, etc.)
- **App Layer Errors**: Protocol parsing errors for all protocols (439+ error metrics)
  - Example: `suricata_app_layer_errors_total{protocol="http",error_type="parser",thread="W#01"}`
- **Detect**: Alerts, rule engine statistics
- **IPS**: Intrusion prevention actions (accept, block, reject, replace)
- **File Store**: File extraction statistics (when enabled)

**Global Metrics** (system-wide aggregates):
- **TCP/Flow Memory**: System-wide memory usage and limits
- **Defrag Memory**: Defragmentation memory usage
- **HTTP/FTP Memory**: Protocol-specific memory capacity
- **Detect Engines**: Rules loaded/failed per engine, last reload timestamp
- **Decoder Events**: Global packet parsing error aggregates
- **App Layer Errors**: Global protocol error aggregates

**v8.0.0 New Protocols**:
- DNS over HTTP/2 (doh2)
- LDAP (ldap_tcp, ldap_udp)
- Multicast DNS (mdns)
- POP3 (pop3)
- SIP split by transport (sip_tcp, sip_udp)
- WebSocket (websocket)

**Total Metrics Coverage**: 900+ unique metrics exported dynamically based on Suricata configuration and active protocols.

### Totals Mode

When using the `-totals` flag, the exporter exports aggregated metrics across all threads instead of per-thread breakdowns. This is useful for:
- Reducing metric cardinality in large deployments
- High-level system monitoring dashboards
- Environments with many worker threads

## Compatibility

**Supported Versions**: Suricata 6.0.4, 7.0.x, 8.0.0+

The exporter is fully backward compatible across Suricata versions:

- ✅ **v6.0.4**: Full support (original development target)
- ✅ **v7.0.x**: Full support with enhanced metrics (flow end states, new protocols)
- ✅ **v8.0.0+**: Full support with latest features (new protocols, enhanced defrag, decoder events)

**Backward Compatibility**: Version-specific metrics use `.Optional()` marking, ensuring the exporter works seamlessly across all supported versions without errors. Metrics not available in older versions are simply skipped.

**Capture Methods**: Tested with AF_PACKET, Netmap, Napatech, and NFQ (netfilter_queue).

**Dynamic Metric Extraction**: The exporter dynamically extracts decoder events and app layer errors from the JSON structure, making it forward-compatible with future Suricata versions without code changes.
