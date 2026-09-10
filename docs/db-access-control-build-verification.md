# DBAC 빌드/검증 진입점

이 문서는 **어떻게 검증하는지**만 다룹니다. 설계 결정은
`db-access-control-phase1-decision.md`와 `db-access-control-phase2-permission-model.md`에 있고
그 두 문서는 변경하지 않습니다.

이 문서가 존재하는 이유는 하나입니다. 잘못된 reactor 진입점을 쓰면 upstream p2 장애와 **똑같이 보이는**
오류가 나고, 실제로 그 오진이 두 라운드에 걸쳐 반복됐습니다. 아래 6절에 그 사고 기록을 남겨 둡니다.

---

## 1. Canonical 진입점: `server/product/aggregate`

전체 backend 검증의 유일한 진입점입니다. `deploy/build-backend.sh:27-28`이 쓰는 것과 같습니다.

```
server/product/aggregate/pom.xml
  modules:
    ../../../../dbeaver-common     <- 형제 저장소
    ../../../../dbeaver            <- 형제 저장소
    ../..                          <- cloudbeaver
```

이 aggregate가 **세 소스 트리를 하나의 Maven session으로 빌드**합니다. `org.jkiss.dbeaver.*` 플랫폼 번들은
로컬 소스에서 만들어지며, p2에서 내려오지 않습니다.

## 2. `server/pom.xml`을 전체 검증에 쓰지 말 것

`server/pom.xml`은 CloudBeaver 자체 모듈(`bundles`, `features`, `product`, `tests`)만 담습니다.
`dbeaver-common`도 `dbeaver`도 포함하지 않습니다. 따라서 이 진입점으로는 플랫폼 번들이 빌드되지 않고,
target platform 해석이 다음과 같이 실패합니다.

```
[ERROR] Cannot resolve project dependencies:
[ERROR]   Software being installed: io.cloudbeaver.model 1.0.108.qualifier
[ERROR]   Missing requirement: io.cloudbeaver.model 1.0.108.qualifier requires
[ERROR]   'osgi.bundle; org.jkiss.dbeaver.data.gis 0.0.0' but it could not be found
```

`-pl <module> -am`으로 범위를 좁히면 같은 이유로 다른 번들이 빠집니다. 예:

```
[ERROR]   Missing requirement: io.cloudbeaver.test.platform 1.0.0.qualifier requires
[ERROR]   'osgi.bundle; org.jkiss.dbeaver.osgi.test.runner 0.0.0' but it could not be found
```

`org.jkiss.dbeaver.osgi.test.runner`는 `dbeaver-common`이 제공하므로 `-am`으로는 절대 들어오지 않습니다.

## 3. Canonical command

```bash
cd server/product/aggregate
mvn -B clean verify -Dheadless-platform
```

`JAVA_HOME`은 JDK 21이어야 합니다. 형제 저장소 `../../../../dbeaver`와 `../../../../dbeaver-common`이
체크아웃되어 있어야 합니다(`build-backend.sh:19-20`이 `--depth 1`로 clone합니다).

실측: 138 modules, 단일 Reactor Summary. `[n/138]`이 권위 있는 숫자입니다 —
`grep -c '^\[INFO\] Building '`로 세면 tycho 하위 단계까지 잡혀 244가 나오므로 그렇게 세지 마십시오.

## 4. PostgreSQL required-mode command

DBAC PostgreSQL 시나리오는 기본이 **optional**입니다. 데이터베이스가 없으면
`DbacSchemaPostgresTest`가 `Assumptions`로 클래스 전체를 skip합니다. 컨테이너가 없는 개발자의
`deploy/build-backend.sh`를 깨지 않기 위한 의도된 동작입니다.

**skip을 실패로 승격**하려면:

```bash
docker run -d --name dbac-pg-test \
  -e POSTGRES_PASSWORD=dbactest -e POSTGRES_DB=dbactest \
  -p 55432:5432 postgres:16-alpine

cd server/product/aggregate
mvn -B clean verify -Dheadless-platform \
    -DdebugArgs=-Ddbac.test.postgres.required=true
```

`-DdebugArgs`가 forked test JVM으로 들어가는 경로입니다: `server/test/pom.xml`이 tycho-surefire의
`argLine`에 `${debugArgs}`를 덧붙입니다. Maven CLI의 `-D`만으로는 fork된 JVM에 전달되지 않습니다.

기본 URL은 `jdbc:postgresql://localhost:55432/dbactest`, 사용자 `postgres`,
비밀번호 `dbactest`이며 `dbac.test.postgres.{url,user,password}`로 덮어쓸 수 있습니다.

> **함정 — 재사용한 컨테이너의 비밀번호는 바뀌지 않습니다.** `POSTGRES_PASSWORD`는 **PGDATA가 비어 있을
> 때 첫 초기화에서만** 적용됩니다. 같은 이름의 컨테이너가 예전에 다른 비밀번호로 만들어져 있으면 위
> `docker run`을 다시 실행해도(또는 env를 고쳐도) 인증은 계속 실패하고, 증상은
> `PSQLException[28P01]: password authentication failed` + `POSTGRESQL NOT VERIFIED`로 나타납니다.
> 이는 제품 결함이 아니며 CI에서는 매번 새 service container를 쓰므로 발생하지 않습니다.
>
> 로컬에서 이 증상을 만나면 **컨테이너를 지우고 다시 만드십시오**:
>
> ```bash
> docker rm -f dbac-pg-test
> docker run -d --name dbac-pg-test \
>   -e POSTGRES_PASSWORD=dbactest -e POSTGRES_DB=dbactest \
>   -p 55432:5432 postgres:16-alpine
> ```
>
> 컨테이너를 지울 수 없는 상황이면 다른 포트에 새로 띄우고 `-Ddbac.test.postgres.url`로 지정하십시오.
> **그 경우 빌드 로그의 green은 기본 URL이 아닌 값으로 얻은 것이므로 보고에 URL을 함께 적습니다.**

검증할 것:
- `Tests run: N, Failures: 0, Errors: 0, **Skipped: 0**`
- 로그에 `POSTGRESQL NOT VERIFIED`가 **0회**
- `DbacSchemaPostgresTest`의 testcase 수가 0이 아님

`Skipped: 0`이 아니거나 `POSTGRESQL NOT VERIFIED`가 보이면 PostgreSQL은 검증되지 않은 것이며,
어떤 보고서에도 검증됨으로 적어서는 안 됩니다.

### CI에서의 강제 방식

required mode는 `push-pr-devel.yml`의 `verify-dbac-postgres` job이 강제합니다.

```yaml
verify-dbac-postgres:
  name: DBAC PostgreSQL
  uses: ./.github/workflows/backend-build.yml
```

그 workflow(`backend-build.yml`)가 `postgres:16-alpine` service와 build step의
`MAVEN_COMMON_OPTS` 추가를 담고 있습니다. job에는 `if:`도 `needs:`도 없으므로
`pull_request`(opened/synchronize/reopened/ready_for_review)와 `devel` push에서 항상 실행되며,
기존 job에 의존성을 만들지 않습니다.

### 빌드가 green이어도 다시 확인합니다 — Surefire 자기검증 step

`backend-build.yml`의 마지막 step `Verify DBAC PostgreSQL scenarios actually ran`이
`.github/scripts/verify_dbac_surefire.py`를 실행합니다(Python 표준 라이브러리만 사용, 새 의존성이나
Action 없음). Maven이 green이라는 것만으로는 PostgreSQL 시나리오가 실제로 돌았다는 증거가 되지
않기 때문입니다 — required property가 없으면 `DbacSchemaPostgresTest`는 `Assumptions`로 abort하고,
abort는 실패가 아니라 skip입니다.

step은 Surefire XML을 읽어 다음을 확인하고, 하나라도 어긋나면 non-zero로 종료해 job을 실패시킵니다.

- 리포트 파일이 존재하고 파싱 가능한 XML인가
- `<properties>`에 `dbac.test.postgres.required=true`가 기록되었는가
  (즉 property가 forked test JVM에 실제로 도달했는가)
- DBAC 5개 클래스의 testcase 수가 정확한가 —
  `DbacSchemaPostgresTest` 21, `DbacSchemaRecoveryTest` 17, `DbacScriptTranslationTest` 9,
  `DbacSchemaTest` 7, `DbacScriptStatementsTest` 6
- 그 testcase에 `skipped` / `failure` / `error` / `flakyFailure` / `rerunFailure`가 하나도 없는가

`<testsuite tests="...">` 속성은 **신뢰하지 않습니다.** 이 스위트에서 그 값은 110인데 실제
`<testcase>`는 117개입니다. 검증기는 항상 `<testcase>` 요소를 직접 셉니다.

step에는 `if:`도 `continue-on-error:`도 없습니다. `if: always()`를 쓰지 않는 이유는, 빌드가
실패한 뒤에도 실행되면 없거나 낡은 리포트 때문에 진짜 원인 위에 혼란스러운 두 번째 오류가
겹치기 때문입니다.

**testcase 수는 의도적으로 하드코딩된 tripwire입니다.** 리포트에서 개수를 읽어오면 절반이 사라진
실행도 통과합니다. DBAC 시나리오를 추가·삭제하면 이 step이 한 번 실패하는 것이 정상이며,
`EXPECTED_DBAC_TESTS`를 손으로 갱신해야 합니다. 클래스를 `CEServerTestSuite`의 `@SelectClasses`에서
빼는 것도 여기서 걸립니다.

로컬에서 직접 돌릴 때는 기본 경로에 CI checkout 접두사(`cloudbeaver/`)가 붙어 있으므로 리포트
경로를 인자로 넘기십시오.

```bash
python .github/scripts/verify_dbac_surefire.py \
  server/test/io.cloudbeaver.test.platform/target/surefire-reports/TEST-io.cloudbeaver.test.platform.CEServerTestSuite.xml
```

**왜 별도 job인가.** PR에서 백엔드를 빌드하는 기존 `build-server` job은
`dbeaver/dbeaver-common/.github/workflows/mvn-package.yml@devel`을 사용합니다. 호출자는 남의
재사용 workflow의 job에 `services:`를 붙일 수 없고, `dbeaver-common`은 이 fork가 수정하지 않는
Platform 저장소입니다. 따라서 PostgreSQL을 붙일 수 있는 유일한 방법이 이 fork 소유
`backend-build.yml`을 호출하는 것입니다.

**대가.** PR마다 백엔드 빌드가 한 번 더 돕니다(로컬 warm 실측 2:25~2:33). 그 대가를 치르지
않으려면 `verify-dbac-postgres` job을 삭제하면 되지만, 그러면 `DbacSchemaPostgresTest`가 CI에서
계속 skip되므로 **어떤 보고서에도 PostgreSQL이 CI에서 검증된다고 적을 수 없습니다.**

### 남은 위험

**timeout이 실측되지 않았습니다.** `backend-build.yml`의 `timeout-minutes: 10`은 이 workflow가
한 번도 실행되지 않은 상태에서 정해진 값입니다. cold runner에서는 postgres image pull,
health 대기, `dbeaver`/`dbeaver-common` clone, Tycho p2 해석, 138 모듈 빌드, 117 테스트,
드라이버 다운로드가 모두 이 안에 들어가야 합니다. 첫 CI 실행으로 실제 소요 시간을 확인하고
근거를 갖고 조정하십시오. 초과하면 코드와 무관하게 PR이 red가 됩니다.

### 해소된 위험 — upstream이 property 전달 경로를 없애는 경우

`dbac.test.postgres.required`는 upstream 소유 파일 `server/test/pom.xml`의
`<argLine>… ${debugArgs}</argLine>` 훅으로만 forked JVM에 도달합니다. upstream 병합이
`${debugArgs}`를 없애면 `REQUIRED`는 조용히 `false`가 되고, 여기에 `findDriverJar()`가 null이
되는 사고(5절의 reactor 순서 의존)가 겹치면 PostgreSQL 테스트가 전부 skip된 채 빌드는
green이 됩니다. 데이터베이스 자체는 정상이므로 service health gate가 이 조합을 잡지 못합니다.

이 구멍은 위의 Surefire 자기검증 step이 막습니다. 리포트의 `<properties>`에
`dbac.test.postgres.required=true`가 없거나 PostgreSQL testcase가 21개가 아니면 step이 실패하므로,
전달 경로가 사라지면 CI가 green이 될 수 없습니다. 따라서 **더 이상 로그를 손으로 확인할 필요는
없습니다** — 다만 upstream 병합에서 `server/test/pom.xml`의 `${debugArgs}`가 사라졌다면, 그때는
이 step이 실패로 알려 줄 것이므로 property 전달 경로를 다시 만들어야 합니다.

## 5. 테스트에 PostgreSQL JDBC 드라이버가 있는 이유

`DbacSchemaPostgresTest.findDriverJar()`는 `user.dir`에서 위로 올라가며
`deploy/drivers/postgresql/postgresql-*.jar`를 찾습니다. `build-backend.sh:7`이 `deploy/drivers`를
지우지만, reactor의 `drivers.postgresql`(130/138)이 `io.cloudbeaver.test.platform`(137/138)보다
먼저 실행되어 드라이버를 다시 받아 놓습니다. 이 순서에 의존하므로, 드라이버 모듈을 테스트 뒤로
옮기면 테스트가 드라이버를 찾지 못합니다.

## 6. 사고 기록 — missing bundle 오류를 p2 장애로 단정하지 말 것

두 라운드에 걸쳐 다음 오진이 있었습니다.

1. `server/pom.xml`로 빌드 → `org.jkiss.dbeaver.data.gis` 해석 실패.
2. `repo.dbeaver.net/p2/ce/26.2.0`의 `content.xml`을 열어 보니 27개 unit뿐이고
   `org.jkiss.dbeaver.*`가 하나도 없었음.
3. "upstream이 26.2.0 채널을 잘랐다"고 결론. **틀렸습니다.**

무엇을 놓쳤는지:

- `p2/ce/*` 채널은 **원래** 서드파티 wrapper만 담습니다. `25.2.0`부터 `26.2.0`까지 전 채널이
  11–15 KB, 27개 내외로 같은 형태입니다. 26.2.0만 이상한 게 아닙니다.
- `org.jkiss.dbeaver.data.gis`는 애초에 p2에서 오지 않습니다.
  `dbeaver/plugins/org.jkiss.dbeaver.data.gis`에 소스가 있고 aggregate reactor가 빌드합니다.
- 진짜 원인은 잘못된 진입점 하나였습니다.

다음에 missing bundle 오류를 보면 **이 순서로** 확인하십시오.

1. 진입점이 `server/product/aggregate`인가? 아니면 그것이 원인입니다.
2. 형제 저장소 `../../dbeaver`, `../../dbeaver-common`이 체크아웃되어 있는가?
3. 없어진 번들이 `org.jkiss.dbeaver.*` 또는 `com.dbeaver.*`인가?
   그렇다면 소스에서 빌드되어야 하는 것이며 p2 문제가 아닙니다.
4. `org.jkiss.bundle.*`(서드파티 wrapper)인가? 그때만 p2를 의심하십시오.

p2 채널이 정말 의심되면 `content.xml`을 **여러 버전에 걸쳐** 비교하십시오. 한 버전만 보면
정상 상태를 장애로 오독합니다.

### 실제로 관측된 유일한 외부 사건

`org.jkiss.bundle.gis 2.0.9`의 SHA-512 불일치가 이전 세션에서 1회 발생했고 재현되지 않았습니다.
이 아티팩트는 채널의 정당한 구성원(27개 중 하나)입니다. `p2/ce/26.2.0`은 개발 중 버전의
**가변 채널**이므로 metadata/artifact skew가 다시 생길 수 있습니다. checksum 검증은 절대 우회하지
마십시오 — Tycho가 잡아 주는 덕분에 조용한 오염이 아니라 빌드 실패로 드러납니다.
---

## 7. invariant sweep — "그 검사만으로 거부되는 테스트가 있는가"

### 왜 필요했는가

`Tests run: N, Failures: 0`은 **테스트가 통과했다**는 뜻이고, **각 보안 검사가 실제로 무언가를 붙잡고
있다**는 뜻이 아니다. 이 프로젝트에서 세 라운드 연속으로 같은 유형의 결함이 나왔다.

```text
생성자에 검사가 있다
  → 그 검사를 겨냥한 테스트도 있다
    → 그런데 그 입력은 다른 검사가 먼저 거부한다
      → 검사를 지워도 스위트는 green
```

즉 테스트가 검사를 **덮고 있는 것처럼 보였을 뿐** 고정하지 못했다. 통과 로그로는 구분되지 않는다.
그래서 판정 기준을 바꿨다 — **검사를 하나씩 지우고, 어떤 테스트가 알아채는지 본다.**

### 1차 sweep의 실패와 그 교훈

1차 sweep(22개 검사, `sweep_checks.py`)은 "22/22 KILLED, unpinned 0건"을 보고했다. **그 주장의 범위가
측정 범위보다 넓었다.** 독립 검토가 두 가지를 지적했다.

| 문제 | 구체적으로 |
|---|---|
| **입도** | 검사 블록 전체만 지웠다. 복합 조건의 **개별 clause**는 건드리지 않았으므로 `requireAgreement`의 `payload.denialReason() != reason` 한 줄이 아무 테스트에도 걸리지 않는 것을 놓쳤다 |
| **목록** | 검사 목록을 손으로 적었다. 그래서 `requireAgreement`라는 helper가 목록에 **아예 없었고**, 그 사실이 "전부 검증"이라는 문장에 드러나지 않았다 |

지워진 clause는 실제 결함을 통과시켰다 — decision은 `NO_GRANT`로 거부하면서 audit row에는
`GRANT_EXPIRED`가 기록되는 조합이 생성자를 통과했다.

### 2차 sweep의 설계 (`sweep2.py`)

교훈을 두 축에 반영했다.

**검사 목록을 손으로 적지 않는다.** 대상 파일을 파싱해서 `if (…) { … throw/return … }` 블록과 clause를
**스스로 찾는다**. 문자열 리터럴·주석을 먼저 지우고(`strip_for_scan`) 괄호 깊이 0의 `&&`/`||`만
분해하므로, 한 파일 안에 새 검사를 추가해도 목록을 갱신할 필요가 없다.

> **[정정] 파일 목록도 손으로 적혀 있었다.** 이 절의 초판은 위 문장을 "새 검사를 추가해도 목록을
> 갱신할 필요가 없다"로 끝냈다. **검사 목록에는 맞고 파일 목록에는 틀렸다.** `sweep2.py`의 `TARGETS`는
> 14개 파일 하드코딩 리스트였고, 독립 QA가 그것이 이미 낡았음을 실측했다 — 이 slice가 **직접 만든**
> `policy/SupportedTargetDatabase.java`·`policy/PolicySnapshotRepository.java`와 이 slice가 **수정한**
> `tempwrite/TempWriteRevokeRequest.java`를 포함해 15개 파일 / 74개 절이 한 번도 sweep되지 않았다.
> 지난 라운드의 결함("검사 목록을 손으로 적어 `requireAgreement`가 목록에 없었다")이 **한 단계 위,
> 파일 입도에서 그대로 재발**한 것이다.
>
> 지금은 `discover_targets()`가 번들의 `src` 트리를 걸어 `.java` 전부를 대상으로 삼고, 제외는
> `EXCLUDE`에 **이름과 이유를 적어** 둔다. 생략으로 암시하지 않는다. 대상은 14개 → **29개 파일**,
> mutant는 205개 → **306개**가 되었다.
>
> QA가 표본 검증한 결과 누락된 절 중 가장 보안 중요한 것(`SupportedTargetDatabase`의
> `driver.isCustom()`)은 이미 고정되어 있었고 실제 우회 구멍은 증명되지 않았다. **그러나 문제는 구멍의
> 유무가 아니라 측정 범위보다 넓은 주장이었다** — 74개 절은 KILLED도 SURVIVED도 아닌 미측정이었고,
> 아래 A~G 목록은 그 14개 파일 안에서만 전수였다.

**입도를 clause 단위로 내린다.**

| mutation | 의미 |
|---|---|
| `del` | 가드 블록 전체 삭제 |
| `clause-k` | 조건의 k번째 top-level clause 제거 |
| `ret-k` | boolean `return` 식의 k번째 clause 제거 (`EndpointSnapshot.matches` 같은 곳) |

탐지기 범위도 한 번 넓혔다. 처음에는 `throw`만 찾았고 `EndpointFingerprints`에서 mutant가 13개만
나왔다 — 그 클래스는 거부를 `return failure(...)`로 표현하기 때문이다. **과소 생성이 문제의 방향**이므로
early `return`도 가드로 취급하고, 무해한 early return은 결과에서 분류해 낸다. 13 → 53으로 늘었다.

### 2단 구조 — 관측자가 못 보는 것을 "고정됐다"고 부르지 않는다

1차 sweep의 관측자는 서버가 필요 없는 test class뿐이다(mutant 당 수 초). 그 관측자가 아예 실행하지
않는 클래스의 mutant는 당연히 살아남는데, **그것을 "고정 안 됨"으로도 "고정됨"으로도 부를 수 없다 —
측정되지 않은 것이다.**

```text
tier 1  서버 없는 관측자(DbAccessPolicyModelTest, TempWriteModelTest)
          ↓ 결정되지 않은 mutant는 survivors.json 으로
tier 2  실제 mvn verify (DbAccessPolicyTest 등 서버 기반 스위트가 관측)
```

`sweep2_tier2.py`가 survivor를 하나씩 실제 빌드에 넣는다. 빌드 시간은 `clean` 없이 110초, `clean`
포함 177초로 실측했으므로 tier 2는 `clean`을 쓰지 않는다. 범위를 줄여 실행할 경우
**escalate하지 않은 mutant를 전부 로그에 남긴다**(`NOT ESCALATED`) — 조용히 자르면 "전부 확인했다"로
읽히기 때문이다.

### 결과를 읽을 때의 주의

* **baseline 마스킹.** tier 1 baseline에서 `DbAccessPolicyModelTest`는 7건이 실패한다(플랫폼 밖에서
  돌 수 없는 config 그룹). mutant가 그 7건만 실패시키면 KILLED로 세지 않는다 — 보수적인 방향이며,
  그만큼 해당 검사들은 tier 2가 판정해야 한다.
* **KILLED 귀속 이름을 믿지 말 것.** `sweep2_tier2.py`가 찍는 "KILLED by X"는 새로 실패한
  testcase를 정렬해 **첫 번째**를 보여 준다. 실제로 구분해 낸 테스트가 아닐 수 있다 — 예컨대 port
  길이 검사 삭제는 `anInactiveUserIsDenied`가 먼저 나오지만, 로그를 열어 보면 판정을 바꾼 것은
  `anOverlongPortIsRefusedRatherThanParsed`이고 그 실패는
  `expected: <ENDPOINT_UNSUPPORTED> but was: <PERMISSION_STORE_UNAVAILABLE>`이다. **어떤 테스트가
  잡았는지 주장할 때는 해당 `tier2-mNNN.log`를 확인한다.**
* **도달 불가능한 중복 방어.** 살아남는 것이 곧 결함은 아니다. 다른 불변식 때문에 **도달 자체가
  불가능한** clause가 있다. 그런 clause는 억지 테스트로 덮지 않고, 코드에 **왜 도달 불가능한지 증명을
  적는다**(`AuthorizationDecision`의 blank grant id, payload decision 비교 두 곳). 테스트로 덮으면
  "검증됐다"는 착시만 되살아난다.

### 의도적으로 생존하는 절 — 전수 목록과 근거

생존이 곧 결함은 아니다. 그러나 **"생존했지만 괜찮다"는 판단은 근거 없이 하면 안 된다** — 그 판단을
근거 없이 한 것이 지난 세 라운드의 결함 유형이었다. 그래서 tier 2를 통과하고도 남은 절 전부를
아래에 분류하고, 각 분류마다 **왜 도달할 수 없는지**를 적는다. 여기에 없는 생존은 결함으로 취급한다.

#### A. package-private record의 shape invariant

| 위치 | 절 |
|---|---|
| `EndpointFingerprints.Result` | `(declared == null) != (failure != null)` |
| `ContainerIdentityResolver.Resolved` | `(key == null) == (failure == null)` |

두 record는 **자기 클래스 안에서만 생성된다.** 테스트는 `io.cloudbeaver.test.platform.dbac` 패키지에
있으므로 package-private 중첩 record에 접근할 수 없고, 직접 잘못된 조합을 만들어 볼 방법이 없다.
가시성을 넓혀 테스트하는 선택은 하지 않았다 — 테스트를 위해 production 캡슐화를 여는 거래이고,
이 invariant는 **같은 클래스 안의 실수**에 대한 방어이므로 그 실수는 컴파일 대상 코드가 바뀔 때만
생긴다.

#### B. 서비스의 앞선 게이트가 먼저 답한다

| 위치 | 절 | 먼저 답하는 것 |
|---|---|---|
| `EndpointFingerprints:172` | `driver == null` | DBMS 지원 검사가 `DBMS_UNSUPPORTED`로 먼저 거부 |
| `EndpointFingerprints:177` | `isBlank(providerId) \|\| isBlank(driverId)` | 같음 — 빈 provider id는 지원 목록에 없다 |

`DbAccessPolicyService`는 endpoint fingerprint **이전에** DBMS 지원 여부를 판정한다. driver가 없거나
id가 비어 있으면 그 단계에서 끝나므로 `EndpointFingerprints.of()`에 도달하지 않는다. `of()`는
package-private이라 테스트가 직접 호출할 수도 없다. 이 절들은 **다른 호출자가 생길 때**를 위한
방어로 남긴다.

#### C. 서로를 가리는 쌍

| 위치 | 절 |
|---|---|
| `EndpointFingerprints:186` | `declaredEndpoint == null` |
| `EndpointFingerprints:201` | `inUseEndpoint == null` |

플랫폼이 두 설정에 같은 객체를 돌려주는 흔한 경우 `inUseEndpoint = declaredEndpoint`이므로 둘 중
하나만 지워도 **다른 하나가 같은 입력을 잡는다.** 두 객체가 실제로 다른 경우에도, 하나를 지우면
`Result` record의 shape invariant가 `IllegalArgumentException`으로 막고 서비스의 외곽 catch가 키를
유지한 DENY로 바꾼다 — 즉 **어느 쪽을 지워도 허용으로는 이어지지 않는다.** 3중 방어이며, 셋 중
둘을 동시에 지워야 결과가 달라진다. mutation은 한 번에 하나만 지우므로 이 구조는 단일 mutation으로
구분되지 않는다.

#### D. 이웃 검사에 포섭됨

| 위치 | 절 | 포섭하는 검사 |
|---|---|---|
| `EndpointFingerprints:320` | leading-zero 검사의 `port.length() > 1` | `"0"`은 range 검사(`>= MIN_PORT`)가 이미 거부 |
| `EndpointFingerprints:268` | `carriesVariable(port)` | `${…}`는 숫자가 아니므로 `isUsablePort`가 먼저 거부 |
| `ContainerIdentityResolver:145` | `registry == null` | 바로 다음 호출을 감싼 `catch (RuntimeException)`이 `false`를 돌려줌 |
| `ContainerIdentityResolver:87` | `userId.isBlank()` | 빈 id는 `new DbAccessKey(...)`가 거부하고, 같은 메서드의 `catch (IllegalArgumentException)`이 **동일한 `IDENTITY_MISSING`** 으로 돌려준다 — reason까지 같다 |
| `DbAccessPolicyService:184` | `!snapshot.userRowPresent()` | snapshot이 두 값을 같은 query에서 뽑으므로(row 없음 → `userRowPresent=false` **및** `userActive=false`) 나머지 절이 같은 입력을 잡는다 |

다섯 절 모두 **지워도 결론이 같다.** 남기는 이유는 결론이 같아도 경로가 다르기 때문이다 — 예외를
던져서 거부되는 것과 검사해서 거부되는 것은 로그와 audit reason이 달라진다. 단 그 차이를
단일 mutation으로 관측할 수 없으므로 테스트로 고정하지 않고 여기에 적는다.

#### E. 플랫폼이 만들지 않는 입력에 대한 null 방어

| 위치 | 절 |
|---|---|
| `EndpointFingerprints:182` | `declared == null` (`getConnectionConfiguration()`가 null) |
| `EndpointFingerprints:288` | `handlers == null` |
| `EndpointFingerprints:292` | handler 목록 원소의 `handler != null` |
| `ConnectionPropertyAllowlist:155` | `map == null` |
| `ConnectionPropertyAllowlist:162` | property key의 `key == null` |

`DataSourceDescriptor`는 항상 `connectionInfo`를 들고 있고, handler 목록에 null 원소를 넣는 API
경로도, property map에 null key를 넣는 경로도 없다. **fixture로 만들 수 없는 상태를 만들려고
production 가시성을 열거나 reflection을 쓰는 것은 하지 않았다.** 이 절들은 upstream이 계약을 바꿀
때를 위한 방어다.

#### F. 다른 불변식이 먼저 거부하므로 도달 불가

| 위치 | 절 | 증명 |
|---|---|---|
| `AuthorizationDecision:145` | `grantId.isBlank()` | 빈 grant id를 가진 allow가 agreement 검사를 지나려면 payload의 grant id도 같은 빈 문자열이어야 하는데, `AuthorizationAuditPayload`가 allow의 빈 grant id를 거부한다 → 그런 payload는 만들 수 없다 |
| `AuthorizationDecision:210` | `payload.decision() != decision` | payload의 decision과 denial reason은 서로 묶여 있고(DENY↔reason 있음, ALLOW↔없음) decision 쪽도 그렇다 → decision이 불일치하면 reason도 반드시 불일치하므로 **다음 절**이 먼저 거부한다 |

두 절은 코드에도 같은 증명이 주석으로 적혀 있다. **테스트로 덮지 않았다** — 덮으려면 다른 절이
먼저 거부하는 입력을 쓸 수밖에 없고, 그것이 바로 이 sweep이 찾아내려는 "검사를 겨냥한 척하는
테스트"다.

#### G. 코드에 이미 도달 불가로 적혀 있는 것

| 위치 | 절 | 근거 |
|---|---|---|
| `DbAccessPolicyService:122` | `category == null` | `WriteAuthorizationRequest`가 생성 시점에 거부한다(그쪽은 테스트로 고정됨) |
| `DbAccessPolicyService:216` | `expiresAt == null` | schema가 `EXPIRES_AT NOT NULL`이다 |

두 절은 **거부하지 않고 던지거나(122), 역참조하지 않고 거부한다(216)** — 도달했다면 그것은 배선
오류이므로 조용히 통과시키지 않는 쪽을 택했다.

### 재현

```bash
python sweep2.py --list                     # mutant 목록만
python sweep2.py                            # tier 1 전체
python sweep2.py --only 'Foo.java:145'      # 수정 확인용 표적 재실행
python sweep2_tier2.py                      # tier 1 survivor를 실제 빌드로
python sweep2_tier2.py 20                   # 20건만, 나머지는 NOT ESCALATED로 기록
```

스크립트는 production 파일을 **제자리에서 변형하고 `finally`에서 복원**한다.

> **[정정] `git status`로는 확인할 수 없다.** 이 절의 초판은 "중단되면 파일이 변형된 상태로 남을 수
> 있으므로 실행 후 `git status`로 확인한다"고 적었다. **이 slice에서는 그 지침이 무효다** — sweep 대상
> 대부분이 아직 untracked 신규 파일이므로, 변형된 채 남은 파일은 `git`에게 "원래 그런 코드"와 구별되지
> 않는다.
>
> 이것은 이론적 위험이 아니었다. 독립 QA가 `sweep2.py`를 파서 재사용 목적으로 `import`했는데 모듈
> 최상위 코드가 즉시 sweep 본체를 실행했고, 프로세스를 죽인 뒤 `AuthorizationDecision.java`는 319행 →
> 305행이 되어 keyless-denial 가드 14행이 사라진 상태였다. **`git status --porcelain`은 그 변형을 전혀
> 보여주지 못했다.** 이번에 살아남은 절은 다행히 테스트가 잡는 절이었지만, 이 sweep은 **"지워도 스위트가
> green인 절"을 이미 목록화해 두고 있다.** 그중 하나를 적용한 상태로 중단되면 git도 테스트도 잡지 못하고
> 신규 파일이므로 그대로 커밋될 수 있다 — **이 프로젝트가 막으려는 바로 그것(강제되지 않는 gate)을 도구가
> 조용히 만들어 내는 경로**였다.
>
> 세 가지를 고쳤다.
>
> | 조치 | 내용 |
> |---|---|
> | `if __name__ == "__main__":` | `import`만으로는 아무것도 변형하지 않는다. 해시 비교로 확인했다 |
> | `MUTATION-IN-PROGRESS` marker | 변형 **전에** 대상 경로와 원본 sha256을 기록한다 |
> | 복원 자기검사 | `restore()`가 복원 후 sha256을 **다시 계산해 원본과 대조**하고, 다르면 예외를 던진다. 다음 실행은 marker가 남아 있으면 **시작을 거부**하고(exit 2) 어느 파일이 어떤 해시여야 하는지 출력한다 |
>
> 따라서 복원 확인은 `git status`가 아니라 **marker 파일의 부재**로 한다.
> `.omx/scratchpad/dbac-slice3/sweep2/MUTATION-IN-PROGRESS`가 없으면 모든 변형이 원본 바이트로 복원된
> 것이다.
