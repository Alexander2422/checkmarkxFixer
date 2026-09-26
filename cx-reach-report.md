# Checkmarx reachability report

Project: `/Users/alex/Downloads/cx-demo`

## Action plan

### 1. Delete these dependencies from pom.xml (nothing uses them)

- `commons-fileupload:commons-fileupload` (CVE-2023-24998); this also removes `commons-io` (CVE-2021-29425)

### 2. Upgrade (still used, can't be excluded)

| Library | Now | Fix version | Why it stays | Clears |
|---|---|---|---|---|
| `org.yaml:snakeyaml` | 1.33 | see advisory (run with --osv) | FRAMEWORK | CVE-2022-1471 |

### 3. Nothing to change in the pom

- `junit:junit` (CVE-2020-15250): NOT-SHIPPED
- `org.apache.activemq:activemq-client` (CVE-2023-46604): NOT-FOUND
- `org.apache.logging.log4j:log4j-core` (CVE-2021-44228): NOT-FOUND

After changing the pom: `mvn dependency:tree` to confirm, `mvn test`, start the app, then rescan with Checkmarx.

## All findings

| Verdict | CVE | Library | Resolved | Brought in by |
|---|---|---|---|---|
| **FRAMEWORK** | CVE-2022-1471 | org.yaml:snakeyaml | 1.33 (compile) | org.springframework.boot:spring-boot-starter-web:3.1.5 |
| **UNUSED** | CVE-2021-29425 | commons-io:commons-io | 2.2 (compile) | commons-fileupload:commons-fileupload:1.4 |
| **UNUSED** | CVE-2023-24998 | commons-fileupload:commons-fileupload | 1.4 (compile) | commons-fileupload:commons-fileupload:1.4 |
| **NOT-SHIPPED** | CVE-2020-15250 | junit:junit | 4.12 (test) | junit:junit:4.12 |
| **NOT-FOUND** | CVE-2021-44228 | org.apache.logging.log4j:log4j-core | - (-) | - |
| **NOT-FOUND** | CVE-2023-46604 | org.apache.activemq:activemq-client | - (-) | - |

### FRAMEWORK - CVE-2022-1471 in snakeyaml 1.33

Your code doesn't reference it, but Spring (spring.factories) or a ServiceLoader lookup loads code that does. Treat as used.

- Severity (Checkmarx): High
- Brought in by: `org.springframework.boot:spring-boot-starter-web:3.1.5`
- Classes reached from your code: 0 of 225
- Hinted vulnerable classes: org.yaml.snakeyaml.constructor.Constructor -> not reached from your code
- Example path:
  ```
  org.springframework.boot.env.YamlPropertySourceLoader
    -> org.springframework.boot.env.OriginTrackedYamlLoader
      -> org.yaml.snakeyaml.Yaml
        -> org.yaml.snakeyaml.constructor.Constructor
  ```
- Note: hint: SnakeYAML: exploitable when parsing untrusted YAML with the default Constructor; SafeConstructor is fine
- Note: hinted vulnerable classes are reachable through the framework path

Pin a fixed version (pom.xml; with the Spring Boot parent you can often just override its version property instead):
```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>FIXED_VERSION</version>
    </dependency>
  </dependencies>
</dependencyManagement>
```

### UNUSED - CVE-2021-29425 in commons-io 2.2

Nothing references it. Exclude it from the dependency that brings it in and re-run your tests.

- Severity (Checkmarx): Medium
- Brought in by: `commons-fileupload:commons-fileupload:1.4`
- Classes reached from your code: 0 of 108
- Hinted vulnerable classes: org.apache.commons.io.FilenameUtils -> not reached from your code
- Note: hint: commons-io FilenameUtils.normalize path traversal

Exclusion (pom.xml):
```xml
<dependency>
  <groupId>commons-fileupload</groupId>
  <artifactId>commons-fileupload</artifactId>
  <exclusions>
    <exclusion>
      <groupId>commons-io</groupId>
      <artifactId>commons-io</artifactId>
    </exclusion>
  </exclusions>
</dependency>
```

### UNUSED - CVE-2023-24998 in commons-fileupload 1.4

Nothing references it. Exclude it from the dependency that brings it in and re-run your tests.

- Severity (Checkmarx): High
- Brought in by: `commons-fileupload:commons-fileupload:1.4`
- Classes reached from your code: 0 of 49

`commons-fileupload` is declared directly in your pom.xml: if you don't need it, delete that `<dependency>` block.

### NOT-SHIPPED - CVE-2020-15250 in junit 4.12

Only test/provided scope - not part of the deployed app.

- Severity (Checkmarx): Medium
- Brought in by: `junit:junit:4.12`

### NOT-FOUND - CVE-2021-44228 in log4j-core 

Not in the resolved tree - probably already upgraded/removed, or the report uses another name.

- Severity (Checkmarx): Critical

### NOT-FOUND - CVE-2023-46604 in activemq-client 

Not in the resolved tree - probably already upgraded/removed, or the report uses another name.

- Severity (Checkmarx): Critical
