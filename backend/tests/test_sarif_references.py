from app.domain.engine.sarif_references import dedupe_defensive_http_urls


def test_sarif_references_keep_defensive_urls_and_filter_direct_poc_links() -> None:
    assert dedupe_defensive_http_urls(
        [
            "GHSA-0000",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
            "https://vendor.example/advisory",
            "https://vendor.example/advisory",
            "https://github.com/example/CVE-2024-0001-poc",
            "https://github.com/rapid7/metasploit-framework/pull/19247",
            "https://github.com/vendor/package/security/advisories/GHSA-0000",
            "https://www.exploit-db.com/exploits/00001",
        ]
    ) == [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
        "https://vendor.example/advisory",
        "https://github.com/vendor/package/security/advisories/GHSA-0000",
    ]
