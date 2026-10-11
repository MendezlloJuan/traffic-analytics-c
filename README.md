# C Network Traffic Metadata Analyzer (Windows)

This sample project summarizes authorized network traffic metadata from JSON Lines (`.jsonl`) files. It measures total bytes, inbound/outbound bytes, average throughput over the observed interval, and latency statistics when valid latency measurements are provided.

## Privacy and scope
- It does not capture packets itself.
- It does not decrypt HTTPS/TLS or inspect packet payloads.
- It does not identify individual users or infer which Instagram Reel/video someone watched.
- Only analyze metadata collected under your organization's authorization and policies.

## Input format
One JSON object per line:
```json
{"timestamp": 1720000000.125, "bytes": 1420, "latency_ms": 18.4, "direction": "in"}
```
Required fields: `timestamp` (Unix epoch seconds) and `bytes` (packet/frame length).
Optional fields: `latency_ms` (a trusted measured latency in milliseconds) and `direction` (`in`, `out`, or `unknown`).

The built-in parser is intentionally small and is suitable for this controlled schema, not arbitrary nested JSON. For production pipelines with arbitrary JSON, use a maintained parser such as cJSON or jsmn and validate input.

## Build on Windows

### Option A: Visual Studio / MSVC
1. Open **x64 Native Tools Command Prompt for Visual Studio** or **Developer Command Prompt for Visual Studio**.
2. Change to this project directory.
3. Run:
   ```bat
   cl /W4 /O2 traffic_analytics.c
   ```
4. Run:
   ```bat
   traffic_analytics.exe sample_traffic.jsonl report.txt
   ```

### Option B: MinGW-w64 GCC
```bat
gcc -std=c11 -Wall -Wextra -O2 traffic_analytics.c -o traffic_analytics.exe
traffic_analytics.exe sample_traffic.jsonl report.txt
```

## Example report
The `example_report.txt` file shows the expected report format. Numeric results are illustrative and depend on the sample input.

## Exporting authorized metadata
Use your approved network monitoring/capture tool to export only the metadata fields needed for operations (timestamps, packet lengths, direction, and latency if the exporter provides a defensible measurement). Avoid collecting payloads or personal identifiers. Do not assume packet timestamps and packet sizes alone provide application-level latency; use an authorized measurement source such as TCP RTT telemetry or synthetic probes where appropriate.

## Limitations
- Average throughput uses `(sum(bytes) * 8) / (last_timestamp - first_timestamp)`.
- Records with invalid/missing timestamps or byte counts are skipped.
- Latency fields are summarized only when supplied.
- This sample reads JSON Lines, not a single JSON array.
- It is a baseline for a controlled pipeline, not a high-performance packet capture engine.
