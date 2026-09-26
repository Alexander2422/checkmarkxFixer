# cx-demo: try the whole flow on a small app

A tiny Spring Boot 3.1 app with **deliberately old, vulnerable libraries**. Each one lands in a different verdict. Don't deploy it.

| Library | Why it's here | Expected verdict |
|---|---|---|
| jackson-databind | `EchoController` parses JSON with `ObjectMapper` | USED (if Checkmarx flags your Jackson version) |
| activemq-client 5.18.2 | `spring-boot-starter-activemq`: the app never uses JMS, but Boot auto-configures it | AUTOCONFIG, critical CVE-2023-46604 |
| snakeyaml 1.33 | Spring Boot reads `application.yml` with it | FRAMEWORK |
| commons-fileupload 1.4 | declared, never used | UNUSED |
| commons-io 2.2 | pulled in *transitively* by commons-fileupload | UNUSED |
| junit 4.12 | test scope only | NOT-SHIPPED |
| log4j-core | not in the project at all | NOT-FOUND (only in the sample CSV) |

The exact CVEs Checkmarx reports depend on its database on the day you scan. The table shows what to expect, not a guarantee.

## 1. Build it
Requirements: JDK 17+ and Maven.
```bash
cd cx-demo
mvn -DskipTests package        # confirms everything resolves and compiles
```

## 2. Try the script without Checkmarx
`checkmarx-sample.csv` is shaped like a Checkmarx export, so you can test straight away:
```bash
python cx_reach.py checkmarx-sample.csv --hints hints.example.json --osv
```
Then open `cx-reach-report.md`: the **Action plan** at the top lists what to delete, exclude and upgrade. `cx-reach-report-pom-changes.xml` has the pom.xml blocks to paste.

## 3. Scan it with Checkmarx
`python cx_reach.py --how-to-export` prints these steps too.

Use whichever of these your company has.

**Checkmarx One web UI**
1. Create a project and upload a zip of this folder, or connect the repo if you've pushed it somewhere.
2. Run a scan with **SCA** enabled.
3. Open the scan, go to **Results → SCA**, then **Export** as CSV or JSON.

**Checkmarx One CLI (`cx`)**
```bash
cx scan create --project-name cx-demo -s . --branch main --scan-types sca
# note the scan ID it prints, then:
cx results show --scan-id <SCAN_ID> --report-format json --output-name cx-results --output-path .
```
Flags can differ between CLI versions. If one is rejected, check `cx scan create --help` and `cx results show --help`. Your team's AppSec people can also tell you how scans are normally run (CI plugin, CLI or UI).

Run the script on the real export:
```bash
python cx_reach.py cx-results.json --hints hints.example.json
```
If it says "no findings recognised", send me the first few lines of the export (package names and CVEs aren't sensitive). I'll adapt the parser to your format.

## 4. Fix and re-scan: watch the criticals disappear
Apply the fixes the report suggests:

- **commons-fileupload / commons-io (UNUSED)** – delete the `commons-fileupload` dependency from `pom.xml`. commons-io goes with it.
- **activemq-client (AUTOCONFIG)** – the app doesn't need JMS, so delete `spring-boot-starter-activemq` and the `spring.activemq` / `spring.jms` lines in `application.yml`.
  If you needed it, you'd set `<activemq.version>` to a patched release (5.18.3 or later) instead.
- **snakeyaml (FRAMEWORK)** – Spring Boot needs it, so you can't remove it. Upgrade it by changing the property to `<snakeyaml.version>2.2</snakeyaml.version>`.

Then verify and rescan:
```bash
mvn dependency:tree -Dincludes=org.apache.activemq,commons-io,org.yaml   # check what's left
mvn test && mvn spring-boot:run                                         # still starts?
cx scan create --project-name cx-demo -s . --branch main --scan-types sca
```
The ActiveMQ critical and the commons-* findings should be gone from the new scan. Run `cx_reach.py` again on the new export too: it should show only what's still there.
