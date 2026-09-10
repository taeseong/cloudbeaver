# DBAC — TEMP_WRITE grant의 물리 endpoint 식별 (DECIDED)

Phase 3 Slice 3 독립 검토에서 **물리 endpoint 승계 우회**가 High로 확인되어 작성한 결정 기록이다.
Phase 2 §5.1의 "스냅샷 3개"(`DRIVER_ID` / `HOST_SNAPSHOT` / `DATABASE_SNAPSHOT`)를 이 문서가 대체한다.

> **인용 기준 checkout (중요).** 이 문서의 platform 줄 번호는 검증에 사용한 격리 트리
> `.omx/scratchpad/dbac-slice3/verify/dbeaver` = **`dbeaver@b59edd3`**(shallow, depth 1) 기준이다.
> 개발용 형제 사본 `D:\IdeaProjects\dbeaver`는 **`1e5ee10`** 이고 `b59edd3` 객체를 가지고 있지 않으므로,
> 그 사본에서는 같은 코드가 다른 줄에 있다(예: connect 시점 사본 생성이 b59edd3에서 `:1114`, 1e5ee10에서 `:1110`).
> 독립 검토가 형제 사본만 보고 hash를 확인할 수 없다고 지적한 것이 이 모호함 때문이다.
>
> **따라서 줄 번호는 보조 정보로만 쓰고, 인용된 메서드 이름을 기준으로 찾는다.** 이 문서가 근거로 삼는
> platform 동작은 아래 메서드들이며, 두 revision에서 의미 차이가 없음을 확인했다.
>
> `DataSourceDescriptor.getActualConnectionConfiguration` / `.connect`(설정 사본 생성) /
> `.disconnect`(early return 및 사본 해제) · `WebSessionProjectImpl.updateConnection` ·
> `DataSourceRegistry.updateDataSource` · `WebDataSourceUtils.setConnectionConfiguration` /
> `.setMainProperties` · `JDBCDataSource.getAllConnectionProperties` /
> `.fillConnectionProperties` · `PostgreDataSourceProvider.getConnectionURL` ·
> `PostgreDataSource.isReadDatabaseList` · `PostgreDatabase`(= `JDBCRemoteInstance` 파생) ·
> `DatabaseURL.generateUrlByTemplate` · `PGProperty.forName` · `PropertyKey.fromValue`

---

## 1. 무엇이 잘못되어 있었는가

`ConnectionSnapshot`이 `(driverId, host, database)` 세 값만 담았다. 그래서 다음이 전부 **ALLOW**였다.

```
grant 부여 시점 : postgresql:postgres-jdbc @ db.internal.example:5432 / customer_prod
그 뒤 편집      : port 만 5432 -> 5433
판정 결과       : 스냅샷 3개가 완전히 동일 -> ALLOW
실제 도달 대상  : 다른 물리 서버 인스턴스
```

`port`는 물리 대상을 바꾸는데 식별자에 없었다. 같은 논리로 다음도 승계되었다.

| 변경 | 예전 결과 | 이유 |
|---|---|---|
| `port` 5432 → 5433 | ALLOW | 비교 대상 아님 |
| `configurationType` MANUAL → URL | ALLOW | 비교 대상 아님. URL mode에서는 host/port/database가 endpoint가 아님 |
| custom JDBC URL만 교체 | ALLOW | `url`이 비교 대상 아님 — **이 행은 schema v3만으로는 닫히지 않았다. §3.4 참조** |
| SSH tunnel `remoteHost`/`remotePort` 변경 | ALLOW | handler가 비교 대상 아님 |
| SOCKS proxy handler 활성화 | ALLOW | 동일 |
| `socketFactory` property 주입 | ALLOW | 동일 |
| driver substitution 지정 | ALLOW | 동일 |

registry 참조 동일성 검사는 이 모두를 막지 못한다. **container 객체가 그대로이고 id도 그대로인 채 설정만 바뀌기 때문이다.**

---

## 2. endpoint identity (DECIDED)

grant는 `(userId, projectId, connectionId)`로 **키가 정해지고**, 아래 6개 값의 **정확 일치**로 그 키가 여전히 같은
물리 대상을 가리키는지 **검증**한다. 하나라도 다르면 `GRANT_STALE` DENY다.

| # | 값 | 출처 | 비교 방식 |
|---|---|---|---|
| 1 | provider ID | `DBPDriver.getProviderId()` | 정확 일치 |
| 2 | driver ID | `DBPDriver.getId()` | 정확 일치 |
| 3 | configuration type | `DBPConnectionConfiguration.getConfigurationType()` | enum 이름 정확 일치 |
| 4 | host | `getHostName()` | 대소문자 무시(DNS는 정의상 대소문자 무시) |
| 5 | port | `getHostPort()` | **문자열 정확 일치.** trim·정수 파싱·leading zero 제거·default port 정규화 모두 하지 않음 |
| 6 | database | `getDatabaseName()` | 대소문자 구분 |

읽는 대상은 **두 곳이며 grant는 둘 다와 일치해야 한다.**

| fingerprint | 출처 | 의미 |
|---|---|---|
| `declared` | `container.getConnectionConfiguration()` | 저장된 설정이 말하는 endpoint |
| `inUse` | `container.getActualConnectionConfiguration()` | 실제로 접속에 사용된 설정. 플랫폼은 접속 시점에 설정을 복사해 disconnect까지 유지한다(아래 각주) |

> **각주 — line number의 기준 commit.** 위 `inUse` 행이 근거로 삼는 세 지점은 형제 저장소 `dbeaver`의
> **commit `1e5ee10`** (이 작업 트리의 HEAD) 기준이다.
> `plugins/org.jkiss.dbeaver.registry/src/org/jkiss/dbeaver/registry/DataSourceDescriptor.java`에서
> `:392-394` = `getActualConnectionConfiguration()`의 `resolvedConnectionInfo != null ? … : connectionInfo`,
> `:1110` = `connect()`가 `resolvedConnectionInfo = new DBPConnectionConfiguration(connectionInfo)`로 사본을
> 만드는 지점, `:1564` = `disconnect()`가 `resolvedConnectionInfo = null`로 되돌리는 지점.
> line number는 upstream 병합마다 움직이므로 **다른 commit에서 확인하면 숫자가 다르다**. 실제로 독립 검토는
> `b59edd3` 기준의 `:396-398` / `:1114` / `:1573`을 제시했고, 그 지적은 옳다 — 두 숫자 집합은 같은 세 코드를
> 서로 다른 commit에서 가리킨다. 숫자를 갱신하는 대신 기준 commit을 적는 쪽을 택한 이유는, 숫자만 고치면 다음
> 병합에서 다시 틀리고 그때는 무엇을 기준으로 쓴 숫자인지 알 수 없게 되기 때문이다. **검증할 때는 숫자보다
> 심볼 이름(`resolvedConnectionInfo`)으로 찾는 편이 안전하다.**

### 2.0 저장본만 읽으면 안 되는 이유 (CORRECTED)

이 문서의 초판은 "`getActualConnectionConfiguration()`은 절대 읽지 않는다 — SSH tunnel이 그 사본의 host를
`127.0.0.1`로 덮어쓰므로 접속 상태에 따라 fingerprint가 달라진다"고 적었다. **그 판단이 틀렸고, 독립 QA가 그것이
남긴 구멍을 찾아냈다.**

CloudBeaver는 저장된 설정을 **제자리에서 수정하고 연결을 끊지 않는다**
(`io/cloudbeaver/WebSessionProjectImpl.java:313-329`가 같은 container 객체를 갱신하고 `DataSourceRegistry.updateDataSource`는
persist + event만 한다. `OBJECT_UPDATE`를 받아 datasource를 끊는 listener는 CloudBeaver에 없다). 따라서:

```
1. admin이 E1 = (..., 5432, prod)에 TEMP_WRITE 부여
2. port를 5433(E2)으로 수정
3. 접속            → 읽기는 write-gated가 아니므로 판정 대상이 아니다. socket은 E2에 열린다
4. port를 5432로 되돌림  → 연결은 끊기지 않는다
5. write 요청      → declared = E1 = grant → ALLOW.  statement는 3에서 열린 E2 socket에서 실행된다
```

즉 **grant가 부여되지 않은 물리 서버에 대한 write가 승인된다.** 이것이 endpoint identity가 막으려던 바로 그
사건이다(§1).

tunnel 논거는 이 누락을 정당화하지 못한다 — **활성 handler는 이미 저장본 기준으로 전부 거부되므로**(§3)
tunnel이 재작성한 사본이 fingerprint 대상이 되는 경우가 없고, profile이 주입하는 handler는 오히려 resolved
쪽에만 나타난다. 따라서 둘을 함께 읽어도 초판이 우려한 불안정성은 생기지 않는다.

대개는 연결이 idle일 때 플랫폼이 저장본 **자체**를 반환하므로 두 fingerprint가 같은 객체다. 다만 **항상 그렇지는
않다** — `DataSourceDescriptor.connect`는 소켓 작업 전에 사본을 만들고(`:1114`), 실패 처리 블록은 `dataSource`만
null로 만들며 그 사본은 그대로 둔다(`:1230-1258`). 사본을 지우는 곳은 `disconnect`의 finally(`:1573`)뿐인데
`disconnect`는 `dataSource == null`이면 early return한다(`:1501-1504`). 따라서 **접속 시도가 실패한 뒤에는
`isConnected()`가 false인데도 별개의 pre-attempt 사본이 반환된다.**

판정은 이 차이에 의존하지 않는다 — 두 사본에 **같은 규칙**을 적용하고 둘 다 grant와 일치할 것을 요구하므로,
실패한 시도 뒤 저장 설정이 바뀌면 사본이 불일치해 DENY다(fail-closed). 그러나 **`isConnected()`가 false일 때
`inUse` 비교를 건너뛰는 최적화를 넣어서는 안 된다** — 그러면 §2.0의 구멍이 다시 열린다. 이 상태는 테스트
`failedAttemptCopyIsStillCompared`로 양방향 고정되어 있다.

### 2.1 빈 port와 driver default port는 같은 endpoint로 정규화하지 않는다

실제 API를 확인한 결과, **플랫폼 소스 어디에서도 빈 `hostPort`에 `DBPDriver.getDefaultPort()`를 대입하지 않는다**
(`DatabaseURL.java:128-130`이 비어 있으면 `[:{port}]` 구간 자체를 생략하고, `PostgreDataSourceProvider.java:110` /
`MySQLDataSourceProvider.java:143`도 대입하지 않는다). "빈 port == 5432"는 **vendor JDBC jar 내부 동작**이며
세 저장소 어디에도 소스가 없고 driver 버전에 고정되지도 않는다(CloudBeaver는 driver jar 교체를 허용한다).

따라서 둘을 같은 endpoint로 보는 것은 **증명되지 않은 전제 위에 ALLOW를 세우는 것**이다.
`CLAUDE.md` §2.1(UNKNOWN → DENY)에 따라 **빈 port는 fingerprint 불가로 보고 거부한다**(§3).

`DBPDriver.getDefaultPort()`는 판정에 사용하지 않는다. mutable 필드이고 driver 편집·legacy import 경로에서
setter로 바뀔 수 있다(`DriverDescriptor.java:738-740`).

### 2.2 credential은 fingerprint·저장·로그에 들어가지 않는다

읽는 것은 위 6개뿐이다. 다음은 **어느 경로에서도 호출하지 않는다.**

```
getUserName / getUserPassword / getAuthProperty / getAuthProperties
getProperty / getProperties / getProviderProperty / getProviderProperties  (값 읽기)
getRuntimeAttribute / getUrl / toString()
getBootstrap().getInitQueries() / getEvent() / getDeclaredEvents()
getAuthModel() / getAuthModelDescriptor()
DBWHandlerConfiguration.getPassword / getSecureProperty / getSecureProperties / saveToMap / saveToSecret
```

`getActualConnectionConfiguration()`은 §2.0에 따라 읽지만, **그 사본에서도 위 6개와 아래 게이트 항목만** 읽는다.
게이트에서 추가로 읽는 것은 `getConfigurationType()` / `getConfigProfileName()` / `getConfigProfileSource()` /
`getAuthModelId()`이며, 마지막 것은 auth model의 **id 문자열**이고 credential이 아니다.

`DBPConnectionConfiguration.toString()`(`:615`)은 그 자체가 유출이므로 금지한다.
`url`은 저장하지도, 해시하지도 않는다 — DBeaver 자신의 generic 템플릿이
`[jdbc:]{driver}://[{user}:{password}@]{host}...`이고 `extractConfigurationFromUrl`이 `password`를 명시적으로
파싱한다(`DatabaseURL.java:37-43, 185-190`). URL 전체 해시는 credential을 해시에 넣는 것과 같다.

`socketFactory` 류 property는 **키 존재 여부만** 확인하고 값은 읽지 않는다(§3).

---

## 3. 지원하지 않는 구성 — `ENDPOINT_UNSUPPORTED`로 fail-closed 거부

안전한 canonical fingerprint를 만들 수 없는 구성은 추측하지 않고 거부한다. 초기 버전의 지원 범위는 다음으로
한정하며, 벗어나면 **`ENDPOINT_UNSUPPORTED`** DENY다.

| 거부 조건 | 근거 |
|---|---|
| `getConfigurationType() != MANUAL` | URL mode에서 `DriverDescriptor.getConnectionURL`은 저장된 `url`을 그대로 반환하고(`:1283-1284`) CloudBeaver는 `hostPort`를 채우지 않는다(`WebDataSourceUtils.java:361-365`). host/port/database가 endpoint가 아니며 stale 값이 그대로 남는다. **다만 이 행만으로는 부족하다 — MANUAL에도 임의의 `url`을 심을 수 있다. §3.4** |
| 저장된 `url`이 비어 있지 않고 **그 설정이 생성했을 url과 다름** | §3.4 |
| `getConfigurationType() == null` | 모드 미확정. UNKNOWN → DENY |
| **활성** network handler가 하나라도 있음 (`isEnabled()`) | `TUNNEL`은 접속 시 host/port를 재작성하고 `remoteHost`/`remotePort`·jump host chain이 실제 경로를 결정한다. `PROXY`는 TCP socket을 재라우팅한다. `CONFIG`(SSL)도 transport를 바꾼다. 이 값들은 plugin.xml에 선언되지 않은 키에 들어 있어 스키마 기반 키 목록으로는 놓친다 |
| config profile 지정 (`getConfigProfileName()` / `getConfigProfileSource()` non-blank) | profile은 접속 시점에 handler를 **주입**하므로(`DataSourceDescriptor.java:1341-1363`) 저장된 handler 목록에 보이지 않는 라우팅이 생긴다 |
| driver substitution 지정 (`getDriverSubstitution() != null`) | `JDBCDataSource.substituteDriverIfNeeded`가 URL과 접속 property를 설정에 없는 코드로 교체한다 |
| host가 blank | endpoint 미확정 |
| port가 blank | §2.1 |
| port가 `^[0-9]{1,5}$`가 아니거나 1~65535 밖 | 플랫폼은 문자열을 그대로 URL에 넣으므로 해석이 vendor 의존이다. UNKNOWN → DENY |
| database가 blank | PostgreSQL은 database 미지정 시 **username으로 대체**하므로 같은 설정이 credential에 따라 다른 database에 도달한다 |
| host / port / database / serverName에 변수 구문 `${` 포함 | `resolveDynamicVariables`는 접속 시점 사본에만 적용되므로 저장된 값은 템플릿이고 실효 endpoint를 알 수 없다. `GeneralUtils.VAR_PATTERN`이 인식하는 형태는 `${...}` 뿐이므로 그것만 검사한다(`@dbeaver-`는 변수 구문이 아니라 내부 property key prefix다) |
| **allowlist에 없는 property 키가 존재** (`properties` / `providerProperties` 어느 쪽이든) | §3.2. **키 존재만 검사하고 값은 읽지 않는다** |
| `getAuthModelId()`가 blank도 `native`도 아님 | `PostgreDataSourceProvider.getConnectionURL:89-100`이 **configuration type 검사보다 먼저** auth model에게 URL 전체를 물어보고 값이 있으면 그대로 반환한다. 즉 `DBPDataSourceURLProvider`를 구현한 auth model이 endpoint를 결정하며 host/port/database는 조회되지 않는다. CE·platform에 그런 auth model은 현재 0건이지만 `authModelId`는 API로 수정 가능하므로 무방비 확장점으로 남겨두지 않는다 |
| `inUse` fingerprint가 위 조건 중 하나에 걸림 | 저장본과 같은 규칙을 접속 사본에도 적용한다(§2.0) |
| driver가 allowlist 밖 또는 `isCustom()` | 기존 `SupportedTargetDatabase` 규칙 |

`ENDPOINT_UNSUPPORTED`는 **key 확정 이후**의 거부이므로 key와 DENY audit payload를 보존한다.

### 3.4 저장된 `url`은 여섯 필드가 생성했을 값과 일치해야 한다 (CORRECTED)

#### 무엇이 틀렸었는가

`EndpointFingerprints.fingerprint`는 `getUrl()`을 **한 번도 읽지 않았고**, 코드에 그 이유가 이렇게
적혀 있었다.

```text
Mode comes from getConfigurationType() and from nothing else. A non-empty url proves
nothing: both the desktop UI and CloudBeaver store a driver-generated url on every save of
a MANUAL connection, so "has a url" is the normal state rather than a signal.
```

**앞 문장은 사실이고 결론이 틀렸다.** 독립 검토가 찾아냈다.

#### 코드 근거

| 지점 | 내용 |
|---|---|
| `dbeaver` `JDBCDataSource.java:402-408` | `getConnectionURL`은 `connectionInfo.getUrl()`이 **비어 있지 않으면 그대로 반환**하고, 비어 있을 때만 driver로 생성한다. **`configurationType`을 보지 않는다** |
| `PostgreDataSource` / `MySQLDataSource` | 이 메서드를 **override하지 않는다**(provider의 동명 메서드는 다른 경로) |
| `WebDataSourceUtils.java:361-365` | `setMainProperties`는 요청의 `url`이 비어 있지 않으면 `dsConfig.setUrl(...)` 후 **즉시 return** — host/port/database를 손대지 않는다 |
| `WebDataSourceUtils.java:323-325` | `configurationType`은 요청에 있을 때만 설정된다. 생략하면 **기존 MANUAL 유지** |
| `WebDataSourceUtils.java:333-338` | url 재생성은 요청 url이 비어 있을 때만. 클라이언트가 준 url은 그대로 저장된다 |

따라서 이런 상태가 만들어진다.

```
grant 부여 시점 : postgresql:postgres-jdbc @ db.internal.example:5432 / customer_prod
그 뒤 편집      : configurationType 은 MANUAL 그대로, 여섯 필드도 그대로,
                  url 만 jdbc:postgresql://other-prod:5432/other_db 로 교체
fingerprint     : declared·inUse 양쪽 모두 grant와 완전히 일치 -> ALLOW
실제 도달 대상  : other-prod 의 other_db
```

**schema v3의 여섯 필드도, declared/inUse 양쪽 비교도 이것을 막지 못한다.** 여섯 필드가 정직하다는
전제 자체가 깨지기 때문이다.

#### 정정된 규칙

저장된 `url`이 비어 있지 않으면, **그 설정이 생성했을 url과 정확히 같을 때만** 통과한다.

```java
String storedUrl = configuration.getUrl();
if (!isBlank(storedUrl)) {
    String generated;
    try {
        generated = driver.getConnectionURL(configuration);
    } catch (Exception e) {
        return null;                       // 생성값을 알 수 없으면 비교할 수 없다
    }
    if (!storedUrl.equals(generated)) {
        return null;                       // 필드가 설명하지 않는 url
    }
}
```

**"비어 있지 않으면 거부"가 아닌 이유.** 옛 주석의 앞 문장이 사실이기 때문이다 — 데스크톱 UI와
CloudBeaver 모두 MANUAL connection을 저장할 때 생성된 url을 함께 저장하므로, 비어 있지 않다는 이유로
거부하면 **모든 정상 연결이 거부된다.** 거부 대상은 "설정이 생성하지 않았을 url"이다.

**url을 스냅샷에 넣거나 hash하지 않는 이유.** §2.2와 같다 — generic driver 템플릿은
`{user}:{password}@`를 포함할 수 있고, 그것이 permission store에 들어가서는 안 된다. 비교는
메모리에서만 하고 어느 쪽 url도 저장·로그하지 않는다.

**부작용(의도된 것).** driver의 sample URL 템플릿이 upstream에서 바뀌면, 예전 템플릿으로 생성돼
저장된 url이 새 생성값과 달라져 그 연결은 `ENDPOINT_UNSUPPORTED`로 거부된다. fail-closed 방향이며,
연결을 다시 저장하면 해소된다. 데스크톱에서 이관했거나 API로 url을 명시해 만든 MANUAL 연결도 같은
이유로 거부된다 — TEMP_WRITE 대상에서 빠질 뿐 조회에는 영향이 없다.

**이 게이트가 기대는 전제 (명시).** 비교의 의미는 `driver.getSampleURL()`이 비어 있지 않다는 데 달려
있다. `DatabaseURL.generateUrlByTemplate`(`dbeaver` `DatabaseURL.java:119-121`)은 템플릿이 비면
**저장된 `url`을 그대로 돌려주므로**, sampleURL이 지워진 driver에서는 `generated == storedUrl`이 항상
성립해 이 게이트가 무효가 된다. driver 정의 편집은 admin(`driverManagement`) 권한이고 §3.1이 driver
descriptor 변조를 시야 밖으로 이미 선언했지만, **이 게이트의 근거가 거기에 걸려 있다는 사실은 암묵으로
두지 않고 여기에 적는다.** 위협 모델에 driver 정의 변조를 넣는다면 `getSampleURL()` blank도 거부
조건에 추가해야 한다.

**DNS는 이 게이트의 범위 밖이다.** host 문자열이 같은 채 이름 해석 대상이 바뀌면 fingerprint는
동일하다. 서버 OS·네트워크 수준 통제의 몫이며, 여기서 다루지 않는다.

**회귀 테스트.** `DbAccessPolicyTest.storedUrlThatContradictsTheFieldsIsRefused` — 여섯 필드는 grant와
일치시키고 url만 host·port·database·query string 각각을 다르게 한 4가지. 기존
`generatedUrlDoesNotMakeItUrlMode`는 **일치하는** url만 고정하고 있어서 이 결함을 잡지 못했다.

---

### 3.2 connection property — denylist를 버리고 allowlist로 (DECIDED, CORRECTED)

초판은 라우팅 위험이 알려진 키 5개(`socketFactory`, `socketFactoryArg`, `proxy.source.url`,
`propertiesTransform`, `sslfactory`)를 거부하고 나머지를 허용했다. **독립 검토가 이를 반려했다** — 코드 주석
자체가 "증명된 완전 목록이 아니다"라고 인정하고 있었고, endpoint identity를 "누군가 떠올린 위험 목록" 위에
세울 수는 없다. 규칙을 뒤집었다.

> **allowlist에 없는 키가 하나라도 있으면, 값과 무관하게 `ENDPOINT_UNSUPPORTED`.**

구현은 `ConnectionPropertyAllowlist`이며 driver별 표다.

| driver | `properties` | `providerProperties` |
|---|---|---|
| `postgresql:postgres-jdbc` | (없음) | (없음) |
| `postgresql:postgresql` | (없음) | (없음) |
| `mysql:mysql8` | (없음) | `@dbeaver-show-all-dbs@` |
| `mysql:mysql5` | (없음) | `@dbeaver-show-all-dbs@` |

#### driver property allowlist가 비어 있는 근거

**일반 웹 생성 연결의 저장된 `properties`는 비어 있다.** CloudBeaver frontend는 driver 기본값과 같은 driver
property를 보내기 전에 제거하고, plugin.xml의 `<property>` 기본값(`loginTimeout`, `connectTimeout`,
`escapeSyntaxCallMode`, `rewriteBatchedStatements`, `enabledTLSProtocols`, `@dbeaver-default-*`)은 connection이
아니라 **`DriverDescriptor`** 에 있다. 따라서 driver property를 전부 거부해도 정상 경로에 비용이 없다.

그리고 비어 있다는 것은 이 표가 **pgjdbc 92개·Connector/J 267개 property 중 무엇이 무해한지에 대해 아무 주장도
하지 않는다**는 뜻이다. 키별 안전성을 직접 검증하지 않았으므로 검증하지 않은 것을 넣지 않았다. 확장은 키별 근거를
이 절에 기록해야 하는 별도 결정이다.

#### `@dbeaver-show-all-dbs@`가 MySQL에만 있어야 하는 근거 (CORRECTED)

초판은 이 키를 PostgreSQL에도 허용하고 그 근거를 "같은 키가 같은 의미"라고 적었다. **틀렸고, 독립 QA가 잡았다.**

| 사실 | 근거 |
|---|---|
| 이 키는 **MySQL 전용**이다 (`MySQLConstants.PROP_SHOW_ALL_DBS`) | `dbeaver/plugins/org.jkiss.dbeaver.ext.mysql/plugin.xml:264`의 `<provider-properties drivers="*">` 안에 `defaultValue="false"`로 선언 |
| PostgreSQL 대응 키는 `@dbeaver-show-non-default-db@`이고 **default가 없다** | `ext.postgresql/plugin.xml:635` |
| PostgreSQL provider property 중 `defaultValue`를 선언한 것은 **하나도 없다** | 위 파일의 provider-properties 블록 |
| frontend는 provider property 기본값을 **제거하지 않고 채워 보낸다** | `ConnectionFormOptionsPart.ts`의 `prepareDynamicProperties` |

따라서 일반 웹 생성 **MySQL** 연결은 이 키를 저장하고, 거부하면 그런 연결은 전부 TEMP_WRITE를 받을 수 없다.
안전한 이유는 둘이다 — driver에 도달하지 않고, 바꾸는 것은 navigator가 나열하는 database 범위다.
**PostgreSQL은 빈 provider map으로 생성되므로 아무것도 허용할 필요가 없다.**

`@dbeaver-show-non-default-db@`는 필요하지 않아서만이 아니라 **적극적인 이유로** 제외한다 — 아래 §3.3.

#### 두 map을 같은 규칙으로, 그러나 서로 다른 key space로

`Driver.connect`에 도달하는 것은 `properties`뿐이다 — `JDBCDataSource.getAllConnectionProperties`가 JDBC
`Properties`를 provider 내부 property + driver descriptor 기본값 + 이 map으로 구성하며 `providerProperties`는
그 경로에 등장하지 않는다. 그래도 provider property에도 "unknown이면 거부"를 적용한다. 이유는 둘이다 —
provider 코드가 `@dbeaver-serverTimezone@`(→ `serverTimezone`)과 `@dbeaver-use-prepared-statements-db@`
(→ `prepareThreshold=0` 억제)를 **driver가 받는 값으로 번역**하고, 분류되지 않은 키는 아무도 생각해보지 않은
키이기 때문이다. 그 두 키는 allowlist에서 제외했다.

#### 비교는 정확 일치

byte 단위 `equals`. trim·대소문자 접기·prefix/substring 없음. driver가 이 map을 읽는 방식과 같다.

| driver | 키 매칭 규칙 |
|---|---|
| pgjdbc 42.7.13 | `PGProperty`가 `HashMap`이고 조회는 `Properties.getProperty(name)` 정확 문자열. 대소문자 무시 alias(`host`/`port`/`dbname` → `PGHOST`/`PGPORT`/`PGDBNAME`)는 **URL query key에만** 적용되며 이 fork는 URL mode를 거부한다 |
| Connector/J 8.2.0 | `PropertyKey` 233 상수 + 34 ccAlias = 267개 이름. per-key `isCaseSensitive`이며 대소문자 무시 11개(`user`, `password`, `host`, `port`, `protocol`, `path`, `type`, `address`, `priority`, `dbname`, `paranoid`)는 전부 ROUTING/AUTH이므로 allowlist에 없다. `socketFactory`는 case-sensitive라 `socketfactory`는 driver가 인식하지 않는 별개 키가 된다 |

관대한 비교는 driver가 **다른** property로 취급하는 표기, 또는 실제 property로 해석하는 표기를 통과시킨다.

#### 값은 읽지 않는다

key set만 본다. property 값은 password·key 경로·URL·클래스 이름일 수 있으므로 값을 읽는 코드가 없고, 키도 값도
decision·audit payload·로그에 넣지 않는다. `datatype.*`(pgjdbc가 클래스로 로드하는 prefix) 같은 것도 allowlist에
없으므로 자동 거부된다.

### 3.3 PostgreSQL 다중 database와 `database` 성분의 의미 (기록)

`PostgreDatabase extends JDBCRemoteInstance`이므로 PostgreSQL은 **database마다 별도 JDBC 연결**을 연다.
즉 fingerprint의 `database` 성분은 "초기 database"이고, 다른 database 인스턴스로 실행하면 grant가 없는 database에
write가 갈 수 있는 구조다.

현재 이것이 막혀 있는 이유는 우연이 아니라 **결합**이다 — `PostgreDataSource.isReadDatabaseList`가
`@dbeaver-show-non-default-db@`를 요구하고, 그 키는 allowlist에 없으므로 그런 연결은 애초에 TEMP_WRITE 대상이
되지 못한다. 결과적으로 grant 적격 PostgreSQL 연결은 fingerprint된 단일 database만 노출한다.

**따라서 운영 편의를 이유로 `@dbeaver-show-non-default-db@`를 allowlist에 추가하면 `database` 성분이 조용히
통제 경계가 아니게 된다.** 추가하려면 database 단위 enforcement를 함께 설계해야 한다.

**MySQL에서는 `database`가 애초에 통제 경계가 아니다 — 코드 근거.** 이전 판은 이 문장을 근거 없이 단정했다.
근거는 `MySQLExecutionContext`다. `setDefaultCatalog`는 `setCurrentDatabaseName`으로 내려가고
(`MySQLExecutionContext.java:159`), 그 구현은 **같은 execution context에서 세션을 열어 `use <db>`를 실행한다**
(`:162-172`, `session.prepareStatement("use " + …)`). 즉 database 전환에 **새 JDBC 연결이 필요하지 않다** —
PostgreSQL이 `PostgreDatabase extends JDBCRemoteInstance`로 database마다 연결을 여는 것과 정반대다.
부트스트랩 경로(`:140-141`)도 같은 메서드를 쓴다.

따라서 **MySQL grant의 실효 범위는 database가 아니라 서버 인스턴스다.** fingerprint의 `database` 성분은
"부여 시점의 초기 database"를 기록할 뿐이고, 한정 이름(`other_db.t`)이나 `use`로 같은 서버의 다른 database에
write가 갈 수 있다. fingerprint는 endpoint 승계를 막기 위한 것이므로 이 성분을 빼지는 않는다 — 다만 그것을
database 단위 격리로 **읽어서는 안 된다.**

> **enforcement slice가 결정할 사항(미결).** MySQL 연결에 TEMP_WRITE를 부여하는 것은 곧 그 서버 인스턴스에
> 쓰기를 허용하는 것이다. 선택지는 (a) 그대로 두고 관리자 UI에 범위를 명시, (b) 부여 시점에 `use`/한정 이름
> 사용을 차단, (c) MySQL을 지원 대상에서 제외. 이 slice는 **선택하지 않았고**, 실행 테스트도 0건이므로
> MySQL을 검증됐다고 표기하지 않는다(§3.1).

### 3.1 남아 있는 한계 (명시)

- **driver descriptor 기본값은 이 검사가 보지 못한다.** plugin.xml `<property>` 기본값은 connection에 저장되지
  않고 `DriverDescriptor`에 있으므로, 저장된 설정을 읽는 이 검사의 시야 밖이다. driver 정의 수준의 변조가
  위협 모델에 포함되면 별도 통제가 필요하다.
- **classpath 수준 기본값.** 함께 번들된 `postgis-jdbc-2.5.0.jar`가 `org/postgresql/driverconfig.properties`를
  포함하고 pgjdbc `Driver.loadDefaultProperties()`가 classpath에서 이를 읽어 connection 기본값으로 쓴다. 연결
  단위 설정이 아니므로 이 검사의 대상이 아니다.
- **MySQL은 검증되지 않았다.** allowlist는 fail-closed(driver property 없음) 상태이지만, MySQL 대상 실행
  테스트는 0건이다. 지원한다고 표기하지 않는다.
- **PostgreSQL 연결에서 provider property를 하나라도 설정하면 그 연결은 TEMP_WRITE 대상이 될 수 없다.**
  "Show all databases", "Show template databases", "Show unavailable databases", user role,
  "Read all data types", `read-keys-with-columns`, `replace-legacy-timezone`,
  `postgresql.dd.plain.string`, `show-database-statistics` 등 전부다. fail-closed이지만
  "정상 경로에 비용이 없다"는 서술은 **웹 폼으로 생성한 기본 상태에만** 해당한다.
- **`data-sources.json`을 직접 작성하거나 desktop에서 이관한 연결은 driver `properties`를 가질 수 있고
  전부 거부된다.** driver property allowlist가 비어 있어도 비용이 없다는 근거는 웹 폼 생성 연결에만 성립한다.
- **`bootstrap.defaultCatalogName` / `defaultSchemaName`은 fingerprint 밖이다.** 웹 API로 설정 가능하고
  statement가 도달하는 catalog를 바꿀 수 있다. endpoint(서버 인스턴스) 변경은 아니며, PostgreSQL에서는 §3.3의
  결합 때문에 현재 실효성이 없다. **게이트에 넣지 않았다** — 정상적으로 default schema를 설정하는 연결을
  거부할 수 있고 그 빈도에 대한 근거가 없기 때문이다. enforcement Slice가 결정해야 하는 항목으로 남긴다.
- **item 5(leading zero 거부)는 우회를 닫은 것이 아니다.** 허용해도 port 비교가 문자열 정확 일치이므로
  `05432`는 `5432` grant와 어긋나 `GRANT_STALE`로 DENY된다. 거부하는 이유는 reason code 위생과
  **fingerprint 단일값성**이다 — 한 서버에 표기가 둘 생기지 않게 한다.
- driver JAR 교체 시 property 이름 공간이 바뀔 수 있다. 현재 표는 pgjdbc 42.7.13 / Connector/J 8.2.0 기준이며,
  driver 버전을 표에 묶는 build-time 검사는 아직 없다.

---

## 4. schema version 3

`DBAC_TW_CURRENT`에 **nullable** 3개를 추가한다.

```
PROVIDER_ID        VARCHAR(128)
CONFIGURATION_TYPE VARCHAR(32)
PORT_SNAPSHOT      VARCHAR(16)
```

nullable인 이유는 하나다 — **version 2 grant에는 이 값이 존재하지 않고, 현재 connection 설정으로 추측해
채우는 것은 금지**이기 때문이다(그렇게 채우면 승계 우회를 migration이 합법화한다).

`DBAC_TW_HISTORY`에는 추가하지 않는다. history에는 원래 스냅샷 컬럼이 없다.

### 4.1 version 2 기존 row의 처리

migration은 값을 만들지 않는다. 따라서 기존 row는 세 값이 NULL이고, 판정은 **NULL을 fingerprint 불완전으로
보아 `GRANT_STALE` DENY**한다. 재부여 전까지 write는 허용되지 않는다.

이것이 의도된 동작이다. version 2 grant는 "port를 검증하지 않은 채 발급된 grant"이므로, 그 grant를 새 규칙에서
유효하다고 인정할 근거가 없다.

---

## 4.2 enforcement 연결 시 필수 acceptance criterion — authorization-to-execution TOCTOU (BLOCKING)

**이번 Slice에서는 구현하지 않는다.** 그러나 enforcement를 연결하는 Slice는 아래를 **차단 조건**으로 만족해야
하며, 만족하기 전에는 READ_ONLY enforcement 완료를 선언하지 않는다.

이 Slice가 닫은 것은 "판정 시점에 두 fingerprint가 grant와 일치하는가"다. 닫지 **못한** 것은 **판정과 실행 사이의
간격**이다. `authorize()`가 ALLOW를 반환한 뒤 statement가 실제로 실행되기까지 다음이 일어날 수 있다.

```
t0  authorize() -> ALLOW   (declared = inUse = grant endpoint)
t1  설정 변경 / reconnect / invalidate
t2  JDBC statement 실행     <- t0의 결정이 더 이상 t2의 대상을 서술하지 않는다
```

`DataSourceDescriptor.connect`는 접속마다 `resolvedConnectionInfo`를 새로 만들고(`:1114`),
`WebSessionProjectImpl.updateConnection`은 연결을 끊지 않고 저장 설정을 제자리 수정한다(`:313-329`). 따라서
t1은 정상 기능이며 예외 상황이 아니다.

### 충족 조건

| # | 조건 |
|---|---|
| A1 | authorization이 확인한 **actual endpoint**와, statement가 실제로 사용하는 **execution context**가 동일함이 보장되어야 한다. 판정이 읽은 설정과 statement가 타는 연결이 같은 객체여야 한다 |
| A2 | statement 생성 **직전**에 재검증하거나, endpoint 변경이 불가능한 동일 context에 결속(bind)해야 한다. "판정 후 곧" 정도로는 부족하다 |
| A3 | `authorize()` 이후 reconnect 또는 configuration update가 발생하면 **이전 decision을 재사용하지 않는다.** DENY하거나 다시 판정한다 |
| A4 | decision을 캐시하거나 세션에 저장하지 않는다. 이 Slice의 판정은 캐시가 없고(테스트로 고정), enforcement가 캐시를 도입하면 A3가 무의미해진다 |
| A5 | 위 조건을 검증하는 자동 테스트가 존재해야 한다. 최소한 "ALLOW 직후 설정 변경 → 실행 차단"과 "ALLOW 직후 reconnect → 실행 차단"을 재현한다 |

### 아직 결정되지 않은 것

A1을 만족하는 방법은 두 가지이고 어느 쪽도 이 Slice에서 결정하지 않았다.

1. `DBCExecutionContext` / `DBCSession` 단위로 결속하여, 판정에 쓰인 context가 아니면 실행을 거부한다.
2. statement 실행 직전에 `authorize()`를 다시 호출하고, 그 사이 endpoint가 바뀌었으면 DENY한다.

전자는 CloudBeaver의 execution context 수명과 재연결 동작을 조사해야 하고, 후자는 metadata 조회 비용이
statement마다 발생한다. **enforcement Slice의 첫 작업은 이 선택의 근거를 조사해 기록하는 것이다.**

---

## 4.3 operation category 어휘의 정정 — `GROUPING`은 write-gated (CORRECTED)

이 항목은 endpoint 식별과 무관하지만, 같은 라운드의 독립 검토가 찾아낸 **분류 오류**이므로 여기에 기록한다.

### 무엇이 틀렸는가

`DbOperationCategory`는 Phase 2 §12.3이 정한 어휘에 없는 두 값을 추가했고, 그중 `GROUPING`을
`NOT_WRITE_GATED`(= 권한 판정 대상이 아님)로 분류했다. 근거로 적힌 javadoc은 다음과 같았다.

```text
A grouping or aggregation query built by the UI over an existing result set
Not write-gated, for the same reason as CONTAINER_READ.
```

**"built by the UI"가 사실이 아니다.** 코드 근거:

| 지점 | 내용 |
|---|---|
| `server/bundles/io.cloudbeaver.server/schema/service.sql.graphqls:456` | `functions: [String!]` — client가 문자열 배열을 그대로 보낸다 |
| `dbeaver` `SQLGroupingQueryGenerator.java:123-124` | `sql.append(", ").append(func)` — 받은 문자열을 생성 SQL에 **검증 없이 이어붙인다** |
| allowlist | **경로 어디에도 없다** |

게다가 이 저장소의 자체 조사 문서 `docs/db-mutation-surface.md` **§13.12**는 이미 같은 결론을 기록해 두고
있었다 — 위험도 **HIGH**, `allowlist = REQUIRED`, "런타임 exploit 확인 여부와 무관". javadoc은 자기 저장소의
조사 결과와 정면으로 모순됐고, 테스트(`assertFalse(GROUPING.requiresWriteAuthorization())`)는 그 주장을
**다시 적기만 해서** 세 라운드 동안 검증된 것처럼 보였다.

### 정정

* `GROUPING` → **`WRITE_GATED`**. client가 보낸 효과 불명의 SQL 조각은 CLAUDE.md §2.1의 UNKNOWN이고,
  UNKNOWN은 DENY 방향이다. 중앙 classifier로 대체할 수 없다는 점도 §13.12가 이미 지적했다 — 주입된 텍스트는
  `SELECT` 안에 들어오므로 `SELECT`로 분류된다.
* 이것이 최종 답은 아니다. allowlist된 집계 함수만으로 만든 grouping query는 읽기이므로, enforcement slice가
  그런 allowlist를 갖추면 재분류할 수 있다. **그때까지는 gate를 거치고, grant가 없으면 거부된다.**
* `CONTAINER_READ`는 `NOT_WRITE_GATED`로 남긴다. 읽기를 막으면 이 프로젝트의 전제(§7: 권한 없음 → READ_ONLY,
  읽기는 허용)가 깨진다. 다만 **범위를 좁혀 명시**했다: 이 값은 navigator의 object tree 읽기이며,
  client가 보낸 filter 식을 실어 오는 데이터 읽기는 **이 범주가 아니다**.

### enforcement slice로 넘기는 미해결 요구사항

`WebSQLDataFilter.makeDataFilter`는 `where`를 `DBDDataFilter.setWhere`로 **검사 없이** 넘긴다
(`server/bundles/io.cloudbeaver.server/src/io/cloudbeaver/service/sql/WebSQLDataFilter.java:118`).
`SQLDataFilter`의 `where` / `orderBy` / `criteria`는 모두 자유 텍스트다. 따라서 enforcement slice는
`functions`와 이 세 필드에 대해 **allowlist를 두거나 write-gate 하거나** 중 하나를 반드시 선택해야 한다.
이 slice는 그 선택을 하지 않았고, **어느 category도 그 경로를 "읽기"라고 답하지 않는다.**

---

## 5. 판정 순서에서의 위치

```
1  rollback            -> ALLOW (무조건)
2  category gate       -> DENY(OPERATION_UNSUPPORTED)   key 없음
3  identity/container  -> DENY(IDENTITY_MISSING/CONNECTION_UNKNOWN)  key 없음
4  DBMS allowlist      -> DENY(DBMS_UNSUPPORTED)        key 보존 + audit payload
5  endpoint 지원 범위   -> DENY(ENDPOINT_UNSUPPORTED)    key 보존 + audit payload
6  metadata 단일 조회
7  user 활성
8  grant 존재
9  만료(회수보다 먼저)
10 회수
11 endpoint fingerprint 일치 -> declared·inUse 둘 다 일치해야 한다.
                          불일치 또는 stored 불완전(v2 row) 시 DENY(GRANT_STALE)
12 clock skew
```

4·5는 metadata connection을 열지 않는다. 그러나 key는 이미 3에서 확정되었으므로 **버리지 않는다** —
"어떤 사용자가 어떤 connection에 대해 범위 밖 write를 시도했다"는 것이 audit에 가장 필요한 사건이다.
key 확정 **이전**의 거부(2·3)만 payload가 없다.
