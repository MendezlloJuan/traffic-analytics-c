/*
 * traffic_analytics.c
 * Analyze authorized network-traffic metadata from JSON Lines.
 *
 * Input schema (one JSON object per line):
 * {"timestamp": 1720000000.125, "bytes": 1420, "latency_ms": 18.4, "direction": "in"}
 *
 * - timestamp: Unix epoch seconds (required)
 * - bytes: packet/frame length in bytes (required)
 * - latency_ms: measured latency in milliseconds (optional; omit or use null if unavailable)
 * - direction: "in", "out", or "unknown" (optional)
 *
 * This program does not capture packets, decrypt TLS, or inspect payloads.
 * Feed it metadata exported by an authorized capture/monitoring tool.
 *
 * Build (MSVC Developer Command Prompt):
 *   cl /W4 /O2 traffic_analytics.c
 *
 * Build (MinGW-w64):
 *   gcc -std=c11 -Wall -Wextra -O2 traffic_analytics.c -o traffic_analytics.exe
 *
 * Run:
 *   traffic_analytics.exe input.jsonl report.txt
 */



#define LINE_MAX_LEN 16384
#define MAX_LATENCIES 1000000

typedef struct {
    double timestamp;
    unsigned long long bytes;
    double latency_ms;
    int has_latency;
    int direction; /* 1=in, 2=out, 0=unknown */
} Record;

static int get_number(const char *line, const char *key, double *out) {
    char pattern[100];
    const char *p;
    char *end;
    if (snprintf(pattern, sizeof(pattern), "\"%s\"", key) >= (int)sizeof(pattern))
        return 0;
    p = strstr(line, pattern);
    if (!p) return 0;
    p = strchr(p, ':');
    if (!p) return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "null", 4) == 0) return 0;
    errno = 0;
    *out = strtod(p, &end);
    if (p == end || errno == ERANGE || !isfinite(*out)) return 0;
    return 1;
}

static int get_string(const char *line, const char *key, char *out, size_t out_size) {
    char pattern[100];
    const char *p, *end;
    size_t n;
    if (snprintf(pattern, sizeof(pattern), "\"%s\"", key) >= (int)sizeof(pattern))
        return 0;
    p = strstr(line, pattern);
    if (!p) return 0;
    p = strchr(p, ':');
    if (!p) return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return 0;
    p++;
    end = strchr(p, '"');
    if (!end) return 0;
    n = (size_t)(end - p);
    if (n >= out_size) n = out_size - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return 1;
}

static int compare_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static double percentile(double *values, size_t n, double pct) {
    size_t idx;
    if (n == 0) return 0.0;
    qsort(values, n, sizeof(double), compare_double);
    {
        double rank = (pct / 100.0) * (double)n;
        idx = (size_t)rank;
        if ((double)idx < rank) idx++;
    }
    if (idx == 0) idx = 1;
    if (idx > n) idx = n;
    return values[idx - 1];
}

int main(int argc, char **argv) {
    const char *input_path = argc > 1 ? argv[1] : "traffic.jsonl";
    const char *output_path = argc > 2 ? argv[2] : "report.txt";
    FILE *in = fopen(input_path, "r");
    FILE *out;
    char line[LINE_MAX_LEN];
    unsigned long long total_bytes = 0, in_bytes = 0, out_bytes = 0;
    unsigned long long packets = 0, skipped = 0;
    double first_ts = 0.0, last_ts = 0.0;
    double latency_sum = 0.0, min_latency = 0.0, max_latency = 0.0;
    double *latencies = NULL;
    size_t latency_count = 0, latency_cap = 0;
    int have_ts = 0;

    if (!in) {
        fprintf(stderr, "Error: cannot open input file '%s'.\n", input_path);
        return 1;
    }

    while (fgets(line, sizeof(line), in)) {
        double ts, bytes_d, latency;
        char direction[32] = "unknown";
        Record r;

        if (!get_number(line, "timestamp", &ts) ||
            !get_number(line, "bytes", &bytes_d) ||
            bytes_d < 0.0 || bytes_d > 9.0e15) {
            skipped++;
            continue;
        }

        r.timestamp = ts;
        r.bytes = (unsigned long long)bytes_d;
        r.has_latency = get_number(line, "latency_ms", &latency) && latency >= 0.0;
        r.latency_ms = r.has_latency ? latency : 0.0;
        r.direction = 0;
        if (get_string(line, "direction", direction, sizeof(direction))) {
            if (strcmp(direction, "in") == 0) r.direction = 1;
            else if (strcmp(direction, "out") == 0) r.direction = 2;
        }

        if (!have_ts) {
            first_ts = last_ts = r.timestamp;
            have_ts = 1;
        } else {
            if (r.timestamp < first_ts) first_ts = r.timestamp;
            if (r.timestamp > last_ts) last_ts = r.timestamp;
        }

        packets++;
        total_bytes += r.bytes;
        if (r.direction == 1) in_bytes += r.bytes;
        if (r.direction == 2) out_bytes += r.bytes;

        if (r.has_latency) {
            if (latency_count == latency_cap) {
                size_t new_cap = latency_cap ? latency_cap * 2 : 128;
                double *tmp;
                if (new_cap > MAX_LATENCIES) new_cap = MAX_LATENCIES;
                if (new_cap <= latency_cap) {
                    fprintf(stderr, "Warning: latency sample limit reached; extra samples ignored.\n");
                } else {
                    tmp = (double *)realloc(latencies, new_cap * sizeof(double));
                    if (!tmp) {
                        fprintf(stderr, "Error: out of memory storing latency samples.\n");
                        free(latencies);
                        fclose(in);
                        return 1;
                    }
                    latencies = tmp;
                    latency_cap = new_cap;
                }
            }
            if (latency_count < latency_cap) {
                latencies[latency_count++] = r.latency_ms;
                latency_sum += r.latency_ms;
                if (latency_count == 1 || r.latency_ms < min_latency) min_latency = r.latency_ms;
                if (latency_count == 1 || r.latency_ms > max_latency) max_latency = r.latency_ms;
            }
        }
    }
    fclose(in);

    out = fopen(output_path, "w");
    if (!out) {
        fprintf(stderr, "Error: cannot write report '%s'.\n", output_path);
        free(latencies);
        return 1;
    }

    {
        double duration = have_ts ? last_ts - first_ts : 0.0;
        double avg_mbps = duration > 0.0 ? ((double)total_bytes * 8.0 / duration) / 1000000.0 : 0.0;
        double avg_latency = latency_count ? latency_sum / (double)latency_count : 0.0;
        double p95 = latency_count ? percentile(latencies, latency_count, 95.0) : 0.0;

        fprintf(out, "NETWORK TRAFFIC SUMMARY\n");
        fprintf(out, "=======================\n");
        fprintf(out, "Input file: %s\n", input_path);
        fprintf(out, "Valid records: %llu\n", packets);
        fprintf(out, "Skipped records: %llu\n", skipped);
        fprintf(out, "Observed duration: %.3f seconds\n", duration);
        fprintf(out, "Total traffic: %llu bytes (%.3f MiB)\n",
                total_bytes, (double)total_bytes / (1024.0 * 1024.0));
        fprintf(out, "Inbound bytes: %llu\n", in_bytes);
        fprintf(out, "Outbound bytes: %llu\n", out_bytes);
        fprintf(out, "Average throughput over observed duration: %.6f Mbps\n", avg_mbps);
        fprintf(out, "Latency samples: %zu\n", latency_count);
        if (latency_count) {
            fprintf(out, "Mean latency: %.3f ms\n", avg_latency);
            fprintf(out, "Minimum latency: %.3f ms\n", min_latency);
            fprintf(out, "Maximum latency: %.3f ms\n", max_latency);
            fprintf(out, "95th percentile latency: %.3f ms\n", p95);
        } else {
            fprintf(out, "Latency: unavailable (no valid latency_ms fields)\n");
        }
        fprintf(out, "\nNOTES\n");
        fprintf(out, "-----\n");
        fprintf(out, "- Throughput is total bytes times 8 divided by elapsed time.\n");
        fprintf(out, "- If all records have the same timestamp, throughput is reported as 0.\n");
        fprintf(out, "- Latency is only meaningful if supplied by a trusted measurement/exporter.\n");
        fprintf(out, "- This report analyzes metadata only; it does not identify video content or users.\n");
        fprintf(out, "- Use only on captures/logs you are authorized to analyze.\n");
    }

    fclose(out);
    free(latencies);
    printf("Report written to %s\n", output_path);
    return 0;
}
