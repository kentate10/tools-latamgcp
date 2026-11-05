import csv
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from gcp_collect import validate_config
from image_rules import base_versions, interpreted_version
from bigquery_live import FILTER_KEYS, _json_filter_pattern, _read_config, query_dashboard, query_project_squads
import artifact_lookup
import scc_browse
from interfaz.server import Store
from scc_collect import classify_resource, image_leaf, normalize_result, query_exact_cve, summarize, summarize_categories, validate_scc_config


class ImageRulesTest(unittest.TestCase):
    def test_interpreted_version(self):
        self.assertEqual(interpreted_version("master-219-abc"), 219)
        self.assertEqual(interpreted_version("219"), 219)
        self.assertIsNone(interpreted_version("latest"))

    def test_base_version_requires_explicit_label(self):
        self.assertEqual(base_versions({"Labels": "base_version=218, version=9"}), [218])
        self.assertEqual(base_versions({"Labels": "version=218", "Tag": "abc218"}), [])

    def test_config_validation(self):
        validate_config({
            "organization_id": "766905427223",
            "artifact_project": "pipeline-corporativo",
            "repositories": [{"location": "us", "name": "application-master"}],
            "max_images_per_repository": None,
        })

    def test_scc_normalization_and_manual_squad_mapping(self):
        item = {
            "finding": {
                "name": "organizations/1/sources/2/findings/3",
                "severity": "HIGH", "state": "ACTIVE", "mute": "UNDEFINED",
                "resourceName": "//container.googleapis.com/projects/demo/clusters/c1",
                "vulnerability": {
                    "cve": {"id": "CVE-2026-12345", "upstreamFixAvailable": True},
                    "offendingPackage": {"packageName": "openssl", "packageVersion": "1"},
                    "fixedPackage": {"packageVersion": "2"},
                },
                "kubernetes": {"objects": [{"containers": [{"uri": "us-docker.pkg.dev/p/r/team/demo-api:219", "imageId": "sha256:abc"}]}]},
            },
            "resource": {"type": "google.container.Cluster", "gcpMetadata": {"projectDisplayName": "demo-prod"}},
        }
        catalog = [{"Artefacto": "Demo API", "Buscar como": "demo-api", "Squad": "Demo Squad"}]
        finding = normalize_result(item, catalog)
        self.assertEqual(finding["cve"], "CVE-2026-12345")
        self.assertEqual(finding["squads"], ["Demo Squad"])
        self.assertEqual(finding["artifacts"], ["Demo API"])
        self.assertEqual(finding["resourceCategory"], "CLUSTERS")
        self.assertEqual(finding["components"], [{"kind": "", "name": "", "namespace": "", "containers": [{"name": "", "uri": "us-docker.pkg.dev/p/r/team/demo-api:219", "imageId": "sha256:abc"}]}])
        counts, groups = summarize([finding])
        self.assertEqual(counts["high"], 1)
        self.assertEqual(groups[0]["active"], 1)
        self.assertEqual(summarize_categories([finding])[0]["uniqueCves"], 1)

    def test_scc_config_and_image_leaf(self):
        validate_scc_config({"scc": {"billing_project": "sp-te-secproject-prod-h5ls", "location": "global", "max_findings": 1000, "request_timeout_seconds": 1800}})
        self.assertEqual(image_leaf("us-docker.pkg.dev/p/r/demo-api:219"), "demo-api")

    def test_resource_categories(self):
        self.assertEqual(classify_resource("google.compute.Instance"), "COMPUTE")
        self.assertEqual(classify_resource("google.artifactregistry.DockerImage"), "ARTIFACTS")
        self.assertEqual(classify_resource("", "", "//run.googleapis.com/projects/p/services/api"), "CLOUD_RUN")
        self.assertEqual(classify_resource("custom.Resource"), "OTHER")

    def test_exact_cve_query_keeps_complete_evidence_without_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "configuracion.json").write_text(json.dumps({
                "organization_id": "766905427223",
                "gcloud_path": "C:/gcloud.cmd",
                "scc": {"billing_project": "sp-te-secproject-prod-h5ls", "location": "global", "max_findings": 1000},
            }), encoding="utf-8")
            fields = ["Artefacto", "Squad", "IT element", "Asignacion", "Observaciones", "Secciones Word", "Buscar como"]
            with (root / "Catalogo.csv").open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerow({"Artefacto": "Demo", "Squad": "Squad A", "Buscar como": "demo"})
            payload = [{
                "finding": {
                    "name": "organizations/1/sources/2/findings/3",
                    "severity": "HIGH", "state": "ACTIVE", "mute": "UNDEFINED",
                    "resourceName": "//compute.googleapis.com/projects/demo/zones/us-east1-b/instances/vm-1",
                    "eventTime": "2026-11-04T12:00:00Z",
                    "vulnerability": {"cve": {"id": "CVE-2026-12345"}},
                },
                "resource": {"type": "google.compute.Instance", "gcpMetadata": {"projectDisplayName": "demo-prod"}},
            }]
            transport = {"transport": "scc-rest-v2", "pages": 1, "totalSize": 1}
            with patch("scc_collect._list_scc_findings_rest", return_value=(payload, transport)):
                result = query_exact_cve("cve-2026-12345", root)
            self.assertEqual(result["rows"], 1)
            self.assertFalse(result["coverage"]["limitApplied"])
            evidence = Path(result["evidenceDirectory"])
            self.assertTrue((evidence / "scc-findings.json").exists())
            self.assertTrue((evidence / "findings-normalizados.json").exists())
            self.assertTrue((evidence / "resultado.md").exists())
            self.assertNotIn("--limit", (evidence / "scc-query.yaml").read_text(encoding="utf-8"))
            self.assertEqual(result["findings"][0]["artifacts"], [])
            self.assertEqual(result["findings"][0]["squads"], ["Por validar asignacion"])

    def test_bigquery_filter_is_parameterized_and_bounded(self):
        pattern = _json_filter_pattern(FILTER_KEYS["squad"], "CoreOps")
        self.assertIn("coreops", pattern)
        with self.assertRaises(ValueError):
            _json_filter_pattern(FILTER_KEYS["squad"], "x' OR 1=1 --")

    def test_bigquery_config_requires_safe_table_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "configuracion.json").write_text(json.dumps({"bigquery": {
                "billing_project": "sp-te-secproject-prod-h5ls",
                "findings_table": "project.dataset.findings;DROP",
                "artifacts_table": "pipeline-corporativo.panel_images.v_container_images_cmdb",
                "cmdb_table": "pipeline-corporativo.itsm_jira_cmdb_dlake.TBL_MASTER_IT-ELEMENT",
            }}), encoding="utf-8")
            with self.assertRaises(ValueError):
                _read_config(root)

    def test_dashboard_rejects_unbounded_date_ranges_before_query(self):
        with self.assertRaises(ValueError):
            query_dashboard("2026-01-01", "2026-03-01", {}, Path("."))

    def test_live_job_keeps_errors_distinct_from_empty_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary))
            with patch("interfaz.server.query_cmdb", side_effect=RuntimeError("BigQuery timeout")):
                job = store.start_live_query("cmdb", {})
                for _ in range(100):
                    state = store.live_job(job["jobId"])
                    if state["status"] != "running":
                        break
                    time.sleep(.01)
        self.assertEqual(state["status"], "error")
        self.assertIn("BigQuery timeout", state["message"])
        self.assertNotIn("result", state)

    def test_project_squads_rejects_unsafe_names_before_query(self):
        with self.assertRaises(ValueError):
            query_project_squads(["x'; DROP TABLE a;--"], Path("."))
        self.assertEqual(query_project_squads(["No determinado", None], Path(".")), {})

    def test_cve_enrichment_failure_keeps_scc_result_and_reports_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary))
            result = {"findings": [{"project": "demo-prod", "squads": ["Por validar asignacion"]}]}
            with patch("interfaz.server.query_project_squads", side_effect=RuntimeError("sin permiso")):
                out = store.prepare_vulnerability_result(result)
            self.assertEqual(out["cmdbEnrichment"]["status"], "error")
            self.assertEqual(out["findings"][0]["squads"], ["Por validar asignacion"])
            with patch("interfaz.server.query_project_squads", return_value={"demo-prod": [{"squad": "Core", "journey": "Cargo"}]}):
                out = store.prepare_vulnerability_result(result)
            self.assertEqual(out["findings"][0]["squads"], ["Core"])

    def test_ui_result_is_bounded_but_keeps_exact_totals(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary))
            rows = [{"state": "INACTIVE" if i % 2 else "ACTIVE", "mute": "UNDEFINED", "project": f"p{i % 7}", "lastSeen": str(i)} for i in range(Store.UI_DETAIL_LIMIT + 123)]
            out = store.limit_for_ui({"findings": rows})
            self.assertEqual(out["stats"]["total"], len(rows))
            self.assertEqual(out["stats"]["projects"], 7)
            self.assertTrue(out["detailTruncated"])
            self.assertEqual(len(out["findings"]), Store.UI_DETAIL_LIMIT)

    def test_scc_browse_filter_builder_is_strict(self):
        text, cve = scc_browse.build_filter("cve-2026-12345", {"state": "ACTIVE", "severity": "HIGH", "resourceType": "google.compute.Instance", "project": "mi-proyecto"})
        self.assertEqual(cve, "CVE-2026-12345")
        self.assertIn('state="ACTIVE"', text)
        self.assertIn('resource.project_display_name="mi-proyecto"', text)
        for bad in ({"state": 'ACTIVE" OR 1=1'}, {"project": 'x" OR state="ACTIVE'}, {"resourceType": 'a" OR b'}, {"severity": "HIGH OR"}):
            with self.assertRaises(ValueError):
                scc_browse.build_filter("CVE-2026-12345", bad)
        with self.assertRaises(ValueError):
            scc_browse.build_filter('CVE-2026-1" OR state="ACTIVE', {})
        with self.assertRaises(ValueError):
            scc_browse.page("CVE-2026-12345", {}, "", 7)

    def test_image_lookup_rejects_unsafe_names_and_parses_refs(self):
        for bad in ("", "ab", "x; DROP", "a b c", "../../etc"):
            with self.assertRaises(ValueError):
                artifact_lookup.lookup(bad, Path("."))
        refs = artifact_lookup._images_in({"spec": "us-docker.pkg.dev/p/application-master/fast_x-y:master-220-280dfa247a", "status": "us-docker.pkg.dev/p/application-master/fast_x-y@sha256:" + "a" * 64})
        entry = refs["us-docker.pkg.dev/p/application-master/fast_x-y"]
        self.assertEqual(entry["tags"], {"master-220-280dfa247a"})
        self.assertEqual(len(entry["digests"]), 1)
        self.assertEqual(artifact_lookup._environment("gke-fast-sisbod-exp-dev"), "dev")
        self.assertEqual(artifact_lookup._environment("bc-co-restart-prod-pmjl"), "prod")

    def test_image_cve_filter_requires_a_real_digest(self):
        digest = "sha256:" + "a" * 64
        text, normalized = scc_browse.build_image_filter(digest.upper(), {"severity": "HIGH"})
        self.assertEqual(normalized, digest)
        self.assertIn(f'resource.name:"{digest}"', text)
        for bad in ("sha256:abc", 'sha256:' + 'a' * 63 + '"', "latest", ""):
            with self.assertRaises(ValueError):
                scc_browse.build_image_filter(bad)
        with self.assertRaises(ValueError):
            scc_browse.build_image_filter(digest, {"state": 'ACTIVE" OR 1'})

    def test_store_loads_without_local_inventory_files(self):
        import shutil, tempfile
        from interfaz.server import Store
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(Path(__file__).parent / "configuracion.json", tmp)
            store = Store(tmp)
            store.load()
            self.assertEqual(store.catalog, [])
            self.assertEqual(store.inventory["images"], [])


if __name__ == "__main__":
    unittest.main()
