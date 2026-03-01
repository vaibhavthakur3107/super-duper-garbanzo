# Network Audit Methodology

## Phase 1 – Host Discovery
- Ping sweep: `nmap -sn 192.168.1.0/24`
- ARP scan (local): `arp-scan --localnet`

## Phase 2 – Port Scanning
- Fast TCP scan: `nmap -sS --top-ports 1000 target`
- Full TCP+UDP: `nmap -sS -sU -sV -sC -T4 -p- target`
- Stealth scan: `nmap -sS -T2 target`

## Phase 3 – Service Enumeration
- Banner grabbing: `nc -nv target port`
- SMB: `enum4linux -a target`, `smbclient -L //target`
- LDAP: `ldapsearch -h target -x -b "dc=domain,dc=com"`
- SNMP: `snmpwalk -v2c -c public target`
- NFS: `showmount -e target`

## Phase 4 – SSL/TLS Audit
- `nmap --script ssl-enum-ciphers -p 443 target`
- Check for: expired certs, self-signed, weak ciphers (RC4, DES, 3DES), no HSTS
- Check TLS version: ensure TLS 1.2+ only

## Phase 5 – Vulnerability Scanning
- `nmap --script vuln target`
- nuclei network templates
- Check for EternalBlue (MS17-010), BlueKeep (CVE-2019-0708)

## Common Findings
- Telnet/FTP open (cleartext protocols)
- Default credentials on network devices
- Unpatched services (check CVE database for version)
- SNMP community string "public" writable
- Anonymous SMB/NFS shares
