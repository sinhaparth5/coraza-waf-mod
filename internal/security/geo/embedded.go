package geo

import "embed"

// embeddedFS contains the bundled MaxMind GeoLite2 Country database.
//
// This product includes GeoLite Data created by MaxMind, available from
// https://www.maxmind.com.
//
//go:embed GeoLite2-Country.mmdb
var embeddedFS embed.FS
