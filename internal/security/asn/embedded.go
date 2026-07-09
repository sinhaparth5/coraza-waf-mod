package asn

import "embed"

// This product includes IP to ASN data created by DB-IP, available from
// https://db-ip.com, licensed under Creative Commons Attribution 4.0
// International License (CC BY 4.0).

//go:embed dbip-asn-lite.mmdb
var embeddedFS embed.FS
