# Enclave Mint Outbound Network Configuration

This document specifies the outbound network configuration required for a Nutshell Cashu Mint instance running within a secure enclave using the Breez / Spark SDK (`SparkL2Wallet`) backend.

Secure enclaves typically block all outbound internet access by default. To allow the Breez Spark SDK to successfully initialize, sync, and process Lightning payments, the enclave host's egress filter or security policy must whitelist the following outbound destinations.

---

## 1. Allowed Egress Domains (Recommended)

If your enclave firewall or network proxy supports domain-level/SNI-based routing (e.g., via Envoy, Squid, or AWS KMS/enclave egress proxies), whitelist the following domains on port **443** (HTTPS):

```text
spark-operator.breez.technology:443
datasync.breez.technology:443
bs1.breez.technology:443
nd1.breez.technology:443
nr1.breez.technology:443
api.lightspark.com:443
0.spark.lightspark.com:443
api.flashnet.xyz:443
2.spark.flashnet.xyz:443
blockstream.info:443
```

---

## 2. IP Address Mapping Reference

For IP-based firewall configurations (such as standard iptables, AWS Security Groups, or CIDR-level white-listing), please refer to the DNS mappings below.

> **Note:** Some of these services use dynamic CDNs (Cloudflare/Cloudfront) or cloud load balancers (AWS ELB) whose IP addresses may rotate periodically. Domain-level whitelisting is highly recommended where possible.

| Target Domain | Resolved IPv4 Addresses | Resolved IPv6 Addresses | Service / Purpose |
| :--- | :--- | :--- | :--- |
| **`spark-operator.breez.technology`** | `54.149.90.91`<br>`32.184.186.45`<br>`44.230.250.110` | None | AWS Load Balancers for Spark Operator |
| **`datasync.breez.technology`** | `66.241.125.214` | `2a09:8280:1::4e:d064:0` | Datasync Service |
| **`bs1.breez.technology`** | `94.23.68.139` | None | Breez Node Service (OVH) |
| **`nd1.breez.technology`** | `94.23.68.139` | None | Breez Node Service (OVH) |
| **`nr1.breez.technology`** | `65.109.145.24` | `2a01:4f9:3051:1ce8:a68f::1d38` | Hetzner Breez Node Service |
| **`api.lightspark.com`** | `54.230.183.61`<br>`54.230.183.28`<br>`54.230.183.94`<br>`54.230.183.57` | None | Lightspark API CloudFront Endpoints |
| **`0.spark.lightspark.com`** | `184.34.92.33`<br>`52.11.91.253`<br>`52.40.137.66` | None | AWS Lightspark Nodes |
| **`api.flashnet.xyz`** | `104.18.23.148`<br>`104.18.22.148` | `2606:4700::6812:1794`<br>`2606:4700::6812:1694` | Cloudflare Flashnet API |
| **`2.spark.flashnet.xyz`** | `104.18.22.148`<br>`104.18.23.148` | `2606:4700::6812:1794`<br>`2606:4700::6812:1694` | Cloudflare Flashnet Spark Node |
| **`blockstream.info`** | `23.155.96.128` | `2620:54:2000:1864::24` | Blockstream Esplora Bitcoin API |
