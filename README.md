# DNS Optimizer

Lightweight Windows IPv4 DNS optimizer written in C. It measures real DNS query latency and response rate against a list of public resolvers. A candidate must answer DNS queries before it can be selected.

The candidate list includes security-oriented resolvers: Quad9 Secure (`9.9.9.9`, `149.112.112.112`), which blocks many known malware/phishing domains; AdGuard DNS (`94.140.14.14`, `94.140.15.15`); CleanBrowsing Security (`185.228.168.9`, `185.228.169.9`); Cloudflare, Google, OpenDNS, Alibaba, Tencent, and 114DNS. The program benchmarks every candidate and selects the fastest responding one, not merely the first listed address. The secondary DNS is also selected by measured latency.

## Build

Install MinGW-w64 GCC and run `build.bat`, or:

```powershell
gcc -O2 -Wall -Wextra -std=c11 -D_WIN32_WINNT=0x0600 dns_optimizer.c -o dns_optimizer.exe -lws2_32 -liphlpapi
```

## Usage

### GUI

Run `dns_optimizer_gui.exe`. It requests administrator permission at startup because changing adapter DNS requires elevation.

1. Click **检测 DNS** to test the current adapter and all candidates.
2. If a candidate is at least 20% faster and a backup resolver is available, **替换 DNS** becomes enabled.
3. Click **替换 DNS** to set the selected resolver as primary and the tested backup as secondary.

The GUI performs network tests on a worker thread, so the window remains responsive. It only uses the first active IPv4 adapter with a gateway and DNS configuration.

### Console

- `dns_optimizer.exe`: one-time measurement only; does not change settings.
- `dns_optimizer.exe --apply`: measure and apply the fastest candidate if it is at least 20% faster than the current DNS. Sets a tested secondary resolver too.
- `dns_optimizer.exe --monitor`: repeat dry-run measurement every 5 minutes.
- `dns_optimizer.exe --monitor --apply`: repeat and automatically apply when the improvement threshold is met.
- `dns_optimizer.exe --help`: show usage.

`--apply` needs an elevated terminal. The program only targets the first active IPv4 adapter with a gateway and configured DNS. If no test candidate responds, it leaves settings unchanged. To revert to DHCP DNS, open adapter IPv4 properties and select "Obtain DNS server address automatically".

Public DNS reachability and performance depend on network policy and location. The benchmark sends a few ordinary A-record queries to each listed resolver; it does not measure privacy, filtering, or DNS-over-HTTPS support. Ordinary UDP/53 DNS is not encrypted, so this version cannot guarantee query privacy. Filtering behavior also varies by resolver and region; security DNS may block domains that are considered unsafe, and no public DNS should be treated as a substitute for endpoint security software.
