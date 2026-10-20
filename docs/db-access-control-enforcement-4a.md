# DBAC Slice 4a — enforcement 계약 (transaction · Explain spine)

> **상태.** Explain/transaction enforcement spine만 연결됨. 만료는 보수적 margin 기반이며 strict real-time
> 보장이 아님. 단일 프로세스 배포 전제이며 multi-node는 지원하지 않음.
>
> 기준 commit: `ac443253842c9532f4ba7a0c4182f455ebfc9b1e`. 이 문서는 그 commit에 실제로 들어 있는 코드와 테스트를
> 기준으로 쓴 최종 계약입니다. 설계 초안이 아니라 동작하는 것을 서술하며, 서술과 코드가 다르면 코드가 맞고
> 이 문서가 틀린 것입니다.

> **아직 미결선 — 이 경로들은 TEMP_WRITE 권한 없이도 DB를 변경할 수 있습니다.**
>
> * 일반 SQL Editor 실행
> * SQL_TEXT classifier와 arbitrary SELECT
> * multiple statements
> * CTE+DML
> * stored procedure / function / anonymous block
> * Data Editor mutation
> * Data Import
> * DDL / Object Editor
> * navigator rename / delete
> * grouping / filter / count의 mutation 가능 경로
> * TEMP_WRITE admin GraphQL API (존재하지 않음)
> * frontend (DBAC UI 없음)
> * MySQL (NOT TESTED)
>
> **`EXPLAIN ANALYZE UPDATE …`를 일반 SQL 실행 API(`asyncSqlExecuteQuery`)로 보내는 경로는 아직 막히지 않았습니다.**
> 막힌 것은 Explain 전용 API(`asyncSqlExplainExecutionPlan`)뿐입니다.

---

## 1. Scope와 명시적 비범위

### 1.1 Scope

Slice 4a는 다음만 연결합니다.

* **enforcement 진입점 세 계열** (2절):
  * transaction 종료 — commit, auto-commit true
  * explicit rollback — 복구 경로이며 판정 대상이 아님
  * Explain
* 그 진입점들이 쓰는 공통 기반:
  * policy core
  * enforcement gate
  * grant/user key lock
  * transaction taint registry
  * pre-execution audit writer
  * bounded metadata lease
  * deployment guard
  * schema version 4 user-incarnation fence

### 1.2 명시적 비범위

* 위 "아직 미결선" 목록 전체. `DbOperationCategory`에는 `SQL_TEXT`, `DATA_EDIT`, `METADATA_DDL`, `IMPORT_DATA`,
  `GROUPING`이 `WRITE_GATED`로 정의돼 있지만, **이 category로 gate를 부르는 production caller는 없습니다**.
  어휘가 있다는 것이 연결됐다는 뜻은 아닙니다.
* 권한 요청, 승인 workflow, 알림(CLAUDE.md §19)
* multi-node 배포 (9절)
* strict real-time 만료 (6절)

---

## 2. 현재 연결된 production entry point

gate를 호출하는 production 코드는 `server/bundles/io.cloudbeaver.server/src/io/cloudbeaver/service/sql/DbacEnforcedExecution.java`
하나뿐입니다. 이 클래스는 `EnforcementGate.global()`만 쓰며 `EnforcementGate.of(...)`는 쓰지 않습니다. 이 사실은
static guard GT-9(`EnforcementGateTest`)가 server bundle 전체 bytecode에서 고정합니다.

| 계열 | GraphQL | 진입 메서드 | adapter 호출 | category |
|---|---|---|---|---|
| transaction 종료 | `asyncSqlCommitTransaction` | `WebSQLContextInfo.commitTransaction()` | `DbacEnforcedExecution.commit` | `TRANSACTION_COMMIT` |
| transaction 종료 | `asyncSqlSetAutoCommit(autoCommit: true)` | `WebSQLContextInfo.setAutoCommit(true)` | `DbacEnforcedExecution.autoCommitOn` | `TRANSACTION_AUTOCOMMIT_ON` |
| explicit rollback | `asyncSqlRollbackTransaction` | `WebSQLContextInfo.rollbackTransaction()` | `DbacEnforcedExecution.rollback` | 판정하지 않음 (복구) |
| Explain | `asyncSqlExplainExecutionPlan` | `WebSQLProcessor.explainExecutionPlan()` | `DbacEnforcedExecution.explain` (recovery 람다 안) | `EXPLAIN` |

* **`setAutoCommit(false)`는 의도적으로 gate 대상이 아닙니다.** auto-commit을 끄는 일은 아무것도 commit하지 않으므로
  upstream 동작을 그대로 둡니다.
* **gate 대상은 위 표의 GraphQL operation이 부르는 transaction 종료뿐입니다.** 미결선 경로가 자기 안에서 끝내는
  transaction은 gate를 거치지 않습니다. 예를 들어 Data Editor의 `WebSQLProcessor.updateResultsDataBatch`는 context가
  auto-commit 모드였다면 auto-commit을 잠시 끄고 batch를 실행한 뒤 platform `commit`을 직접 부르고 auto-commit을
  되돌립니다. SQL 문으로 보낸 `COMMIT`도 일반 SQL 실행 경로(미결선)를 탑니다.
* `setAutoCommit(true)`가 들어왔을 때 JDBC 자체가 이미 auto-commit이면 gate 판정(`run()`)과 platform 호출 없이 바로
  성공합니다(`enter()`와 X·M 획득은 이미 일어난 뒤입니다). 열린 transaction이 없으니 commit될 것도 없습니다. platform
  cache 값은 기준으로 쓰지 않습니다.
* Explain은 Slice 4a에서 **모두 write-gated**입니다. plain `EXPLAIN`, `EXPLAIN ANALYZE`, configuration 유무와
  상관없습니다. `EXPLAIN ANALYZE`는 statement를 실제로 실행하기 때문입니다. READ_ONLY 사용자는 모든 Explain이
  거부됩니다. 의도된 기능 제한이며, configuration allowlist와 `ANALYZE` 차단이 테스트로 고정되기 전에는 재허용하지 않습니다.
* **기능 회귀 (배포 즉시).** ADMIN 예외는 없고, grant를 발급하는 API도 없습니다(13절 R18). 따라서 배포하면 사실상
  **모든 사용자**에게 다음이 거부됩니다.
  * Explain 전체. manual commit 모드에서 거부되면 그 context의 열린 transaction도 **rollback**됩니다(3.2).
  * Commit 버튼(`asyncSqlCommitTransaction`). 거부되면 열린 transaction은 **rollback**됩니다(3.2).
  * manual commit 모드에서 auto-commit 다시 켜기. 이것도 거부되면 열린 transaction이 rollback되고, 사용자는
    auto-commit을 다시 켤 수 없습니다.
  * allowlist 밖 DBMS(예: Oracle, SQL Server)에서는 grant가 있어도 위 작업이 `DBMS_UNSUPPORTED`로 거부됩니다.
  * allowlist 안의 PostgreSQL이라도 endpoint를 식별할 수 없는 연결은 grant가 있어도 `ENDPOINT_UNSUPPORTED`로
    거부됩니다. SSH tunnel 같은 network handler를 켠 연결, allowlist에 없는 provider·driver property를 가진 연결이 해당합니다
    (endpoint-identity 3절).
* adapter의 Explain entry(`explain`, `ExplainCall`)는 package-private입니다. 같은 package의 `WebSQLProcessor`만
  부를 수 있습니다.

---

## 3. 권한 판정 순서

판정은 세 층으로 이루어집니다. 아래 순서가 실제 코드 순서입니다.

### 3.1 adapter — gate 이전 (audit 0, K/U 0)

`DbacEnforcedExecution`은 async task 안에서 다음을 차례로 확인합니다.

1. `EnforcementGate.global().enter()`
2. 현재 execution context를 새로 조회
3. 판정
   * context가 없으면 `CONNECTION_UNKNOWN`
   * JDBC가 아닌 context는 `ENDPOINT_UNSUPPORTED`
     * commit과 auto-commit on에서는 transaction manager가 없는 context에 한해 upstream no-op으로 둡니다.
     * Explain은 항상 거부합니다.
4. X → M
5. generation 조회. 없으면 `CONNECTION_UNKNOWN`
6. JDBC `getAutoCommit()` 조회
7. generation 재확인. 다르면 `GRANT_STALE`

이 단계의 거절은 key를 아직 모르므로 audit row를 남기지 않습니다. gate의 거절 경로(`run()`)를 타지 않으므로 열린
transaction을 rollback하지도 않습니다. transaction은 commit되지 않은 채 그대로 남습니다(TA-4, XA-6). platform 호출도
없습니다.

### 3.2 gate — `EnforcementGate.Entry.run()`

1. **admission.** `enter()`가 policy service holder의 READY 여부와 deployment guard의 단일 프로세스 확인을 봅니다.
   실패하면 `PERMISSION_STORE_UNAVAILABLE`이고, key를 모르므로 audit 0입니다.
2. **key 해석.** metadata를 열지 않고 user·project·connection key를 정합니다.
3. **grant key K read lock.** `T_k` 안에 못 잡으면 `PERMISSION_STORE_UNAVAILABLE`.
4. **user U read lock.** `T_k` 안에 못 잡으면 `PERMISSION_STORE_UNAVAILABLE`.
5. **taint 상태.** `TAINTED`면 `TRANSACTION_TAINTED`, `BLOCKED`면 `CONNECTION_BLOCKED`.
6. **expiry window를 열고 policy core로 authorize** (3.3). 결정이 잠근 key와 다른 key를 가리키면
   `PERMISSION_STORE_UNAVAILABLE`.
7. **check-1** (6절).
8. **audit budget claim** → **`WRITE_ALLOWED` insert**.
   * budget claim이 실패하면 `PERMISSION_STORE_UNAVAILABLE`입니다. allowed row가 아직 없으므로 correction이 아니라
     일반 `WRITE_DENIED`를 남깁니다.
   * insert가 실패하면 `AUDIT_WRITE_FAILED`이고 correction row를 남깁니다(7절).
9. **check-2** (6절).
10. **holder가 여전히 `enter()` 때의 그 READY인지** 확인.
11. **caller의 최종 확인.** 실제 connection이 아직 같은 generation인지 봅니다. 다르면 `GRANT_STALE`.
12. **`Execution.execute()`.** platform 호출은 여기에만 있습니다.

어느 단계에서 거절되든 같은 경로로 나갑니다(5절). 순서는 다음과 같습니다.

1. transaction이 열려 있으면 rollback
2. registry에 상태 기록
3. key를 알면 `WRITE_DENIED`
4. 거절 사유 반환

lock은 성공·거절·예외 어느 경우에도 U → K 순서로 반환됩니다.

### 3.3 policy core — `DbAccessPolicyService.authorize`

| # | 단계 | 거절 사유 |
|---|---|---|
| 1 | recovery category(rollback) | 무조건 ALLOW — gate에는 오지 않음 |
| 2 | write-gated가 아닌 category | `OPERATION_UNSUPPORTED` (key 없음) |
| 3 | identity · container | `IDENTITY_MISSING` / `CONNECTION_UNKNOWN` (key 없음) |
| 4 | target DBMS allowlist | `DBMS_UNSUPPORTED` |
| 5 | endpoint 식별 가능성 | `ENDPOINT_UNSUPPORTED` |
| 6 | metadata snapshot 한 statement (`T_s`) | 읽기 실패 시 `PERMISSION_STORE_UNAVAILABLE` |
| 7 | user 존재·활성 | `USER_INACTIVE` |
| 8 | grant 존재 | `NO_GRANT` |
| 9 | 만료 (DB 시각으로 판정) | `GRANT_EXPIRED` |
| 10 | 회수 | `GRANT_REVOKED` |
| 11 | endpoint fingerprint — declared와 in-use 모두 일치 | `GRANT_STALE` |
| 12 | 이 node 시계와 DB 시계의 skew | `CLOCK_SKEW_EXCEEDED` |
| 13 | 잔여 수명 `EXPIRES_AT − DB_NOW` > 0 | 아니면 `PERMISSION_STORE_UNAVAILABLE` |

예상하지 못한 예외는 모두 `PERMISSION_STORE_UNAVAILABLE`입니다. 판정은 캐시하지 않습니다.

---

## 4. lock 순서와 revoke/user-deactivation 선형화

| 기호 | lock | 대기 |
|---|---|---|
| X | instance exclusive lock (`JDBCRemoteInstance.getExclusiveLock()`, thread 재진입) | 무기한 (platform) |
| M | context monitor (`synchronized (JDBCExecutionContext)`) | 무기한 |
| K | grant key의 fair `ReentrantReadWriteLock` read | `T_k` (기본 5초) |
| U | user의 fair `ReentrantReadWriteLock` read | `T_k` |

* **획득 순서:** `enter()` (X 획득 전) → X → M → K → U
* **해제 순서:** U → K (gate의 `finally`) → M → X (adapter)
* **explicit rollback:** X, M만 잡습니다. K·U, policy, metadata, audit은 쓰지 않습니다.

writer 쪽 (`EnforcementKeyLocks`를 쓰는 곳):

| 작업 | lock | 위치 |
|---|---|---|
| TEMP_WRITE grant | K write (무기한) → U read (`T_k`) → user 존재 확인 | `TempWriteMutationCoordinator.grant` |
| TEMP_WRITE revoke | K write (무기한) | `TempWriteMutationCoordinator.revoke` |
| 사용자 비활성화 | U write (무기한). connection을 받는 overload는 auto-commit에서만 허용 | `DbacEmbeddedSecurityController.enableUser(…, false, …)` |
| 사용자 삭제 | U write + live grant 존재 시 거부 | `DbacEmbeddedSecurityController.deleteUser` |
| 팀 삭제 | 팀 id에 대한 U write | `DbacEmbeddedSecurityController.deleteTeam` |

**선형화.** 진행 중인 attempt는 platform 호출이 끝날 때까지 K·U read를 유지합니다.

* revoke나 비활성화는 그 attempt가 끝난 뒤에 commit됩니다.
* writer가 대기 중이면 fair lock 때문에 그 뒤에 온 attempt는 writer 다음 순서가 됩니다. 그 attempt는 writer가
  끝난 뒤 새 상태를 읽고 거부되거나, `T_k`를 넘겨 `PERMISSION_STORE_UNAVAILABLE`로 거부됩니다.
* 따라서 **K·U write를 잡는 writer가 끝낸 revoke·비활성화 이후에 시작된 platform 호출은 없습니다.** 반대로 revoke를
  요청했다고 진행 중인 operation이 중단되지는 않습니다. revoke의 응답은 그 operation이 끝날 때까지 늦어집니다(13절).

**적용 범위.** 이 선형화는 위 표의 writer를 거칠 때만 성립합니다.

* 사용자 비활성화·삭제와 팀 삭제는 production에서 `DbacEmbeddedSecurityController`를 거칩니다(`CBApplicationCE`가
  `DbacSecurityControllerFactory`로 연결).
* **TEMP_WRITE grant·revoke의 `TempWriteMutationCoordinator`는 Slice 4a에서 production caller가 없습니다.** 관리자
  API가 없기 때문입니다. 운영에서 grant나 revoke를 하려면 metadata DB를 직접 수정할 수밖에 없고, 그 수정은 K를 잡지
  않으므로 **선형화되지 않습니다.** 판정을 이미 통과해 audit·check-2 구간에 있던 attempt는 그런 revoke가 commit된
  뒤에도 platform을 호출할 수 있습니다(13절 R19). 그 다음 attempt는 새 snapshot을 읽고 `GRANT_REVOKED`로 거부됩니다.

이 lock들은 JVM-local입니다. 같은 metadata DB를 쓰는 두 번째 프로세스가 있으면 선형화가 성립하지 않으므로
deployment guard(9절)가 그것을 전제로 둡니다.

---

## 5. transaction taint와 BLOCKED lifecycle

`TransactionTaintRegistry.global()`은 context마다 `CLEAN`(entry 없음) / `TAINTED` / `BLOCKED`를 둡니다.

* **identity.** platform context id와 context 객체 자체를 함께 씁니다. 객체는 `==`로 비교하고 weak reference로
  잡습니다. 같은 id에 다른 살아 있는 객체가 오면 `IllegalStateException`이 나고, gate는 이를
  `PERMISSION_STORE_UNAVAILABLE`로 처리합니다.
* **open transaction 판정.** JDBC `getAutoCommit()`이 `true`가 아니면 열린 것으로 봅니다. 읽지 못해도 열린 것으로 봅니다.
* **거절 시 처리** (gate SEC):

  ```
  active? ─ no ─▶ 기록 없음
     │ yes
     ▼
  markTainted ─▶ bounded rollback ─ 성공 ─▶ rollbackSucceeded (CLEAN)
                                   └ 실패 ─▶ sever ─▶ markBlocked (BLOCKED)
  ```

  * bounded rollback: 같은 thread, 같은 X/M 아래에서 실행합니다. JDBC network timeout은 10초입니다.
  * sever: connection을 `abort`한 뒤 `invalidateContext(BEFORE_INVALIDATE)`를 호출합니다. connection을 pool에 정상으로
    돌려주지 않습니다.
* **platform 호출 뒤 postcondition 실패:**
  * 해당하는 경우
    * commit 뒤 generation 교체
    * auto-commit on 뒤 JDBC가 여전히 manual
    * auto-commit 호출 예외
    * Explain 뒤 generation 교체
  * 처리: adapter가 TAINTED → bounded rollback → sever → BLOCKED 순서로 처리하고 `CONNECTION_BLOCKED`로 거부합니다.
  * correction audit은 쓰지 않습니다.
* **BLOCKED 해제:** 살아 있는 connection에서 explicit rollback이 성공해야만 풀립니다(`releaseAfterExplicitRollback`).
  * gate 자신의 rollback 성공으로는 BLOCKED가 풀리지 않습니다.
  * sever(`BEFORE_INVALIDATE`)와 reconnect는 QM close 알림을 내지 않으므로 BLOCKED가 그대로 남습니다.
  * explicit rollback이 실패하면 sever 후 BLOCKED를 유지하거나 새로 설정합니다.
* **context close:** QM close handler가 `contextClosed`로 entry를 지웁니다. physical connection과 함께 transaction도
  끝났기 때문입니다.
* **service 정지:** registry가 `clear()`되고 닫힙니다. 닫힌 registry는 `state`에 답하지 않으므로 이후 gate는
  `PERMISSION_STORE_UNAVAILABLE`로 거부합니다.

---

## 6. expiry window와 strict real-time 한계

* 만료는 **metadata DB 시각**으로 판정합니다(snapshot statement 안의 `EXPIRES_AT > CURRENT_TIMESTAMP`).
  * 잔여 수명은 그 statement가 읽은 두 값에서 계산합니다.
  * 경과 시간은 이 node의 monotonic clock(`System.nanoTime()`)으로, window를 연 시점(snapshot statement 전)부터 잽니다.
    snapshot에 걸린 시간까지 경과 시간에 들어가므로 보수적인 방향입니다.
* **check-1** (audit 전): `remaining − elapsed > T_audit + δ`
* **check-2** (audit 후): `remaining − elapsed > δ`
* audit budget은 check-1이 예약한 `T_audit` 그대로입니다. 따라서 audit이 budget 안에 끝나면 check-2 시점에 δ 이상이
  남습니다.
* 기본값(`DbAccessPolicyConfig`):

  | 값 | 기본 |
  |---|---|
  | δ (expiry guard margin) | 1초 |
  | `T_audit` | 2초 |
  | `T_s` | 2초 |
  | `T_k` | 5초 |
  | clock skew 한도 | 5초 |
* retry는 새 window를 엽니다. window는 attempt 하나에만 속합니다.

**strict real-time 보장이 아닙니다.**

* check-2 뒤에는 시계를 다시 보지 않습니다. check-2와 platform 호출 사이에 δ보다 긴 정지가 있으면, platform 호출은
  `EXPIRES_AT` 이후에 시작될 수 있습니다. 정지 원인으로는 GC, VM pause, scheduling, driver 내부 대기가 있습니다.
* 이 한계는 XA-15(EX-3)가 **의도된 동작으로 고정**합니다. check-2가 허용한 뒤 planner 진입을 멈추고 만료를 지나게
  해도 plan은 실행됩니다.
* 이미 시작된 commit·auto-commit·Explain은 만료 시각이 지나도 끝까지 진행됩니다. platform 호출 자체에는 시간 상한이
  없습니다(13절).
* VM pause, host suspend 동안 `System.nanoTime()`이 어떻게 진행하는지는 플랫폼마다 다르며 검증하지 않았습니다.

---

## 7. pre-execution audit 의미

* **`WRITE_ALLOWED`는 platform 실행 성공 기록이 아닙니다.** 그 attempt의 authorization이 통과했고, platform 호출 **전에**
  audit insert가 commit됐다는 뜻입니다.
  * platform은 그 뒤에 실패할 수도 있고 BLOCKED가 될 수도 있습니다.
* **platform 호출 뒤에는 correction `WRITE_DENIED`를 쓰지 않습니다.** `WRITE_DENIED` row는 항상 "platform이 호출되지
  않았다"는 뜻입니다.
* **`WRITE_ALLOWED` 뒤 platform 호출 전에 상태가 바뀌어 거부되면** correction row를 남깁니다. 해당하는 경우는 check-2,
  holder 변경, generation 확인 실패, audit 실패입니다.
  * correction은 **새 event ID**의 `WRITE_DENIED`입니다.
  * key, grant, category, expiry는 같은 값을 씁니다.
  * allowed row의 기록이 실패로 보고됐더라도 correction을 남깁니다. 실제로는 commit됐을 수 있기 때문입니다.
* **key를 모르는 거절에는 audit row가 없습니다.**
  * gate 안의 거절(admission 실패, holder가 READY가 아님, key 해석 실패)은 그래도 열린 transaction을 rollback합니다.
  * adapter 사전 거절(3.1)은 gate의 거절 경로를 타지 않으므로 audit도 rollback도 하지 않습니다(TA-4).
* **audit 저장소에 의존하는 경우:**
  * metadata capacity가 포화되거나 저장소 장애가 나면 denial row조차 기록되지 않을 수 있습니다. 그래도 operation은
    **DENY**됩니다.
  * allowed row를 쓰지 못하면 `AUDIT_WRITE_FAILED`로 거부하고 platform은 호출하지 않습니다.
* **row 내용** (`DBAC_AUDIT_EVENT`):
  * 기록 항목: `EVENT_ID`(UUID), `EVENT_TYPE`, `EVENT_TIME`, `USER_ID`, `ACTOR_ID`, `PROJECT_ID`, `CONNECTION_ID`,
    `GRANT_ID`, `OPERATION_CATEGORY`, `DECISION`, `DENIAL_REASON`, `EXPIRES_AT`
  * `STATEMENT_TYPE`은 `NULL`입니다.
  * SQL 전문, URL, host, credential은 넣지 않습니다.
* **DBAC 로그:** 고정 event code, 새 `EVENT_ID`, 예외 class 이름, 고정 detail(step·거절 사유 같은 enum 이름)을
  남깁니다. policy core(`DbAccessPolicyService`)의 로그는 여기에 더해, key를 알면 URL-encode한 user·project·connection
  id(`key=`)도 남깁니다.
  * SQL, configuration, URL, host, credential, driver message, stack trace는 남기지 않습니다.
  * XA-16, P1 redaction 테스트가 이를 확인합니다.
* **잔여 위험(별도).** upstream 경로는 driver message나 SQL을 노출할 수 있습니다.
  * GraphQL 오류의 stack frame — `WebServerError`, Explain의 `DBWebException` wrapper
  * `WebServiceSQL`의 `monitor.subTask("Explain query [" + sql + "] …")`
  * `DBExecUtils.tryExecuteRecover`의 recovery 로그
  * planner 내부 오류 로그

  DBAC 계약 밖이며 13절에 기록합니다.

---

## 8. connection generation/recovery 계약

* **generation:** context의 현재 JDBC `Connection` 객체(`getConnectionOrNull()`)입니다.
  * X+M 아래에서 읽고 바로 재확인합니다.
  * gate의 최종 확인과 platform 호출 뒤 사후 확인에서 다시 비교합니다.
  * X+M을 쥔 동안 platform은 connection을 교체할 수 없습니다. `connect`는 X 아래, `disconnect`는 M 아래에서 일어납니다.
* **platform 호출 전 교체:** `GRANT_STALE` 거절, correction row를 남기고 platform 호출은 0입니다(TA-6, XA-5).
* **platform 호출 뒤 교체:** 성공으로 보고하지 않습니다. BLOCKED, `CONNECTION_BLOCKED`, correction 0입니다(TA-7, XA-14).
* **commit과 auto-commit true:** 현재 user, container, context, generation을 async task **안에서** 다시 읽습니다.
  * task 생성 시점에 잡아 둔 값은 쓰지 않습니다(TA-2 bytecode).
  * request의 `executionContextId`는 실제 context id입니다.
  * container는 GraphQL 인자가 아니라 실제 context의 data source에서 가져옵니다.
* **Explain recovery** (`DBExecUtils.tryExecuteRecover` 람다 안):
  * attempt마다 다음을 새로 만듭니다(XA-2, XA-17).
    * gate entry
    * context, generation
    * authorization
    * expiry window
    * audit row
  * **DBAC 거절은 recovery를 일으키지 않습니다.**
    * 거절 예외(`Refusal`)는 SQLState·cause·stack이 없으므로 platform이 `NORMAL`로 분류합니다.
    * 따라서 invalidate나 retry가 없습니다(XA-4, TA-16).
  * **connection-lost만 retry합니다** (platform의 `CONNECTION_LOST`/`TRANSACTION_ABORTED` 분류).
    * planner의 실제 connection-lost 예외는 그 의미를 유지합니다.
    * platform은 attempt가 반환되고 X·M·K·U가 모두 풀린 **뒤에** invalidate하고 다시 시도합니다(XA-2).
  * **retry 전에 revoke가 완료되면** 다음 attempt는 planner 호출 없이 `GRANT_REVOKED`로 거부됩니다(XA-3).
  * **check-2 뒤에 만료가 지나도** 이미 승인된 callback은 실행될 수 있습니다(6절, XA-15).
* commit, auto-commit, rollback 진입점에는 platform recovery loop가 없습니다.
* endpoint 식별과 declared configuration 변경의 의미는 `docs/db-access-control-endpoint-identity.md` §4.2(A5)와 §4.2.1을
  보십시오.

---

## 9. deployment invariants — 위반 시 배포 중단

### 9.1 공통

* `dbac.deployment=single-process`
  * `test`는 test bundle이 있을 때만 허용합니다.
  * 값이 없거나 다르면 policy service가 READY가 되지 않고, 모든 write-gated 작업이 DENY됩니다.
* **multi-node / distributed 배포는 지원하지 않습니다.** CE의 multi-node 선언은 하드코딩된 `false`입니다. 이것은
  탐지가 아니라 선언입니다.
* JVM-local K/U lock과 taint registry가 맞으려면 `DeploymentGuard`가 단일 프로세스를 보장해야 합니다.
* metadata lease capacity **4**는 integration 값이지 production sizing 값이 아닙니다.
  * 동시에 5번째 metadata 요청이 오면 즉시 `PERMISSION_STORE_UNAVAILABLE`로 거부될 수 있습니다.
  * 실제 배포 부하와 retry UX를 검증하기 전에는 production 준비 완료를 선언하지 않습니다.

### 9.2 H2 metadata

* 검증된 embedded H2 release만 허용합니다: `h2_embedded_v2` + 2.1.214, `h2_embedded_v3` + 2.4.240.
  다른 조합은 refuse합니다.
* production에서 in-memory H2는 금지입니다. test mode에서만 허용합니다.
* local file만 지원합니다. remote(`tcp:`/`ssl:`), relative path, 알 수 없는 sub-protocol은 refuse합니다.
* **network filesystem은 금지입니다.** NFS, SMB/CIFS, mapped drive, RWX shared volume 등이 해당합니다. guard는 이를
  탐지하지 않으므로 운영자가 지켜야 합니다.
* UNC / authority-style path는 `H2_NETWORK_PATH`로 refuse합니다.
* URL은 printable ASCII만 받습니다. 비 ASCII 경로는 fail-closed로 거부될 수 있으므로 권장하지 않습니다.

### 9.3 PostgreSQL metadata

* session-level advisory lock을 유지할 수 있는 **직접 PostgreSQL session**이 필요합니다.
* PgBouncer transaction/statement pooling을 포함해, transaction·statement pooling proxy는 금지입니다.
* PostgreSQL protocol 호환 engine은 PostgreSQL로 간주하지 않으며 지원하지 않습니다.
* **guard는 위 두 가지를 탐지하지 않습니다.** driver가 보고하는 product name으로는 구분할 수 없으므로 운영자가
  지켜야 합니다.
* lock owner는 `(pid, backend_start)`로 식별합니다. lock을 잡는 statement가 그 값을 함께 읽습니다.
  * owner 확인은 advisory, granted, exclusive, 정확한 key, 이 DB, 그 pid와 그 시작 시각이 모두 맞아야 합니다.
* `backend_start`를 관찰할 수 있어야 합니다. 같은 DB role을 쓰거나 관찰 권한이 필요합니다.
* 관찰할 수 없거나, query timeout이 나거나, 결과가 모호하면 DENY합니다.
* 실제 network partition에서 pgjdbc cancel과 socket timeout의 상한은 검증하지 않았습니다.
* `source.open()`과 guard 내부 lock의 완전한 시간 상한은 보장하지 않습니다.

---

## 10. schema version 4 migration 영향

* metadata schema **3 → 4**. 구조 변경은 없습니다(`server/bundles/io.cloudbeaver.service.dbac/db/dbac_schema_update_4.sql`은 주석과 `SELECT 1;`뿐인, 의도적으로 아무것도 바꾸지 않는 script).
* **최초 업그레이드 시 철회되지 않은 TEMP_WRITE grant를 전부 영구 revoke합니다.** 만료 여부와 상관없습니다.
  * 각 revoke마다 `REVOKED` history event를 씁니다.
  * migration transaction 안에서, revision compare-and-set으로 처리합니다.
  * 하나라도 실패하면 전체가 rollback되고, version은 3으로 남으며, server가 시작되지 않습니다.
* 운영자는 업그레이드 뒤 필요한 grant를 **다시 부여**해야 합니다.
* **v4 DB는 v3 binary로 되돌릴 수 없습니다.** v3 build는 v4 DB에서 시작을 거부합니다.
* 복구는 업그레이드 전에 **별도로 받아 둔 metadata DB backup**을 복원하는 방법뿐입니다. migration runner의 내장 backup이
  DBAC 복구에 쓸 수 있는지는 검증하지 않았습니다.
* migration과 runtime user-incarnation fence는 같은 binary tree에 있습니다.
  * deletion fence: live grant를 가진 사용자는 삭제를 거부합니다.
  * grant fence: 사용자의 U read lock 아래에서, 존재하는 사용자에게만 grant합니다.
  * 셋이 `USER_FENCE_SINCE_VERSION`을 공유하므로 어긋날 수 없습니다.

---

## 11. 지원·검증 DBMS

| 대상 | 상태 |
|---|---|
| target DB — PostgreSQL (`postgresql`/`postgres-jdbc`, `postgresql`/`postgresql`) | policy allowlist 포함. enforcement integration 테스트로 검증(PostgreSQL 16, `postgres:16-alpine`) |
| target DB — MySQL (`mysql`/`mysql8`, `mysql`/`mysql5`) | policy allowlist에 포함되어 있으나 **NOT TESTED**. 지원 또는 검증되었다고 주장하지 않습니다 |
| 그 밖의 DBMS | `DBMS_UNSUPPORTED`로 DENY |
| metadata — H2 embedded | 9.2의 조건에서. server test는 H2 in-memory(test mode)로 실행 |
| metadata — PostgreSQL | 9.3의 조건에서. guard·lease·audit·migration을 PostgreSQL metadata schema로 검증 |
| Explain planner | PostgreSQL planner만 검증 |

---

## 12. 테스트와 verifier 증거

* 기준 commit: `ac443253842c9532f4ba7a0c4182f455ebfc9b1e`
* 실행 방식: P6-B 최종 batch, PostgreSQL required mode, `server/product/aggregate` clean verify
* frozen evidence 위치: 작업 트리의 git-ignored 로컬 증거 저장소입니다. 저장소에 commit되지 않습니다.
  * `.omx/scratchpad/dbac-slice4a/s1/p6b/final-green-full/TEST-io.cloudbeaver.test.platform.CEServerTestSuite.xml`
  * `final-hashes.sha256` = `final-inputs-at-batch-start.sha256` = `final-inputs-at-batch-end.sha256`

| 항목 | 값 | 출처 |
|---|---:|---|
| full suite | 686 PASS (failure·error·skip 0) | P6-B `final-green-full` |
| PostgreSQL testcase (verifier) | 274 | `verify_dbac_surefire.py`, P6-B XML |
| DBAC testcase (verifier) | 629 | 같음 |
| `TransactionEnforcementEntryPointTest` | 12 | 같음 |
| `TransactionEnforcementAdapterTest` | 19 | 같음 |
| `ExplainEnforcementEntryPointTest` | 2 | 같음 |
| `ExplainEnforcementAdapterTest` | 17 | 같음 |
| `EnforcementGateTest` | 35 | 같음 |
| P6-A mutants | 26/26 rejected | `.omx/scratchpad/dbac-slice4a/s1/p6a/final-kills.txt` (입력 = commit `5bc8259`) |
| P6-B mutants | 18/18 rejected | `.omx/scratchpad/dbac-slice4a/s1/p6b/final-kills.txt` (입력 = commit `ac44325`) |
| LC-6 lifecycle failure matrix | runs 1296, violations 0 | P6-B `final-green-full/build.log`의 `[DBAC P3] LC-6 failure matrix` |

* verifier는 `<testcase>` 요소를 직접 셉니다. `<testsuite tests>` 속성은 신뢰하지 않습니다.
* 클래스별 고정값은 `docs/db-access-control-build-verification.md` §9를 보십시오.
* 이 문서를 commit해도 새 testcase는 생기지 않으므로 verifier 숫자는 바뀌지 않습니다.

---

## 13. 알려진 위험

| # | 위험 | 영향 |
|---|---|---|
| R1 | **strict real-time expiry가 아님.** check-2 뒤 δ를 넘는 정지가 있으면 만료 후 platform 호출 가능 | XA-15로 고정된 의도된 한계 |
| R2 | **VM pause / monotonic clock 한계.** `System.nanoTime()`의 suspend 동작은 검증하지 않음 | 경과 시간을 과소 측정할 수 있음 |
| R3 | **긴 commit, auto-commit, Explain 동안 revoke·비활성화 완료가 지연됨.** 진행 중인 attempt가 K·U read를 쥔 채 platform을 호출함 | revoke 응답 지연. `EXPLAIN ANALYZE SELECT pg_sleep(…)`처럼 길이를 TEMP_WRITE 사용자가 정할 수 있음. 새 attempt는 `T_k` 뒤 DENY |
| R4 | **platform 호출 자체에 시간 상한이 정해지지 않음** (commit, `setAutoCommit`, planner) | X·M·K·U 보유 시간에 상한 없음 |
| R5 | **rollback network timeout(10초)이 driver 내부 lock까지는 제한하지 못함** | 다른 statement가 driver lock을 쥐면 rollback 대기에 상한 없음 |
| R6 | **rollback / auto-commit / sever의 `Error` 경로는 테스트하지 않음.** `boundedRollback`은 `Error`를 잡지 않음. explicit rollback 중 `Error`가 나면 sever와 BLOCKED를 건너뜀 | 미검증. explicit rollback에서는 이전 상태가, platform 호출 뒤 사후조건 실패 경로에서는 `TAINTED`가 남음. 어느 쪽이든 이후 시도는 gate가 판정하고, `TAINTED`면 `TRANSACTION_TAINTED`로 거부 |
| R7 | **raw SQL `BEGIN`·`START TRANSACTION`과 JDBC autoCommit flag 불일치.** flag가 true면 열린 transaction으로 보지 않음 | 미결선인 SQL 경로를 연결하기 전 차단 조건 |
| R8 | **audit store가 포화되면 denial row가 누락될 수 있음** | operation은 DENY. 기록만 빠짐 |
| R9 | **advisory-lock 검사 경로가 완전히 bounded는 아님** (`source.open()`, 내부 lock, network partition) | admission 지연 가능 |
| R10 | **MySQL NOT TESTED** | 지원을 주장하지 않음 |
| R11 | **upstream error wrapper, monitor, recovery log의 SQL·driver detail 노출** (7절) | DBAC 계약 밖의 잔여 노출 |
| R12 | **일반 SQL과 다른 mutation path가 미결선** | READ_ONLY 사용자가 그 경로로 DB를 변경할 수 있음 |
| R13 | metadata capacity 4 포화 시 PSU 거부 (9.1) | 부하 상태에서 정상 사용자도 거부될 수 있음 |
| R14 | 안 B의 declared-only 변경 경로를 다루는 전용 barrier 테스트 없음. 근거는 CH-10과 policy endpoint 테스트 (endpoint-identity §4.2.1) | 테스트 공백 |
| R15 | Explain·transaction entry 수준의 user/connection 격리 전용 테스트 없음. 공용 `request()`와 policy 테스트에 의존 | 테스트 공백 |
| R16 | **multi-node / distributed 배포 미지원.** K/U lock과 taint registry가 JVM-local이고, CE의 multi-node 선언은 탐지가 아니라 하드코딩된 `false`임. pooling proxy, protocol 호환 engine, network filesystem도 guard가 탐지하지 않음 (9절) | 두 번째 프로세스가 같은 metadata DB를 쓰면 선형화·taint·만료 판정의 전제가 깨짐. 운영자가 단일 프로세스를 보장해야 함 |
| R17 | **schema v4 migration은 되돌릴 수 없음.** 최초 업그레이드 때 철회되지 않은 TEMP_WRITE grant를 만료 여부와 상관없이 전부 revoke함. v3 build는 v4 DB에서 시작을 거부함 (10절) | 업그레이드 뒤 필요한 grant를 다시 부여해야 함. 복구 수단은 업그레이드 전에 따로 받아 둔 metadata DB backup뿐 |
| R18 | **기능 회귀.** ADMIN 예외와 grant 발급 API가 없으므로, 배포 즉시 사실상 모든 사용자에게 Explain, Commit 버튼, manual 모드의 auto-commit 켜기가 거부되고, 거부 시 열린 transaction이 rollback됨. allowlist 밖 DBMS와 endpoint를 식별할 수 없는 연결(SSH tunnel 등)은 grant가 있어도 거부됨 (2절) | 사용자 작업 중단과 미commit 변경 손실. 배포 전에 사용자에게 공지해야 함 |
| R19 | **metadata DB를 직접 수정한 grant·revoke는 K lock을 잡지 않아 선형화되지 않음.** grant·revoke coordinator는 production caller가 없음 (4절) | 판정을 이미 통과한 attempt는 그런 revoke가 commit된 뒤에도 platform을 호출할 수 있음. 다음 attempt부터 거부 |

---

## 14. 다음 Slice에서 연결할 mutation path

| 경로 | 진입 (예) | 비고 |
|---|---|---|
| 일반 SQL 실행 | `asyncSqlExecuteQuery` → `WebServiceSQL.asyncExecuteQuery` → `WebSQLUtils.createAsyncTaskExecuteSqlQuery` → `WebSQLProcessor.processQuery` | SQL_TEXT classifier 필요. arbitrary SELECT(function side effect), multiple statements, CTE+DML, procedure/function/anonymous block, raw `BEGIN`(R7), `EXPLAIN ANALYZE <DML>`을 포함해야 함 |
| Data Editor | `updateResultsDataBatch`, `asyncUpdateResultsDataBatch`, `updateResultsDataBatchScript` | `DATA_EDIT` |
| Data Import | `dataTransferImportDataIntoResults` | `IMPORT_DATA` |
| DDL / Object Editor | SQL 실행 경로, object 편집 | `METADATA_DDL` |
| navigator rename / delete | `navRenameNode`, `navDeleteNodes` | DB object rename/drop |
| grouping / filter / count | `sqlGenerateGroupingQuery`, `asyncReadDataFromContainer`(filter `where`/`orderBy`), `asyncSqlRowDataCount` | 자유 텍스트 조각. allowlist 또는 write-gate 필요(endpoint-identity §4.3) |
| TEMP_WRITE 관리 | (GraphQL API 없음) | 서버 측 관리자 권한 검증이 필요 (CLAUDE.md §21) |
| frontend | (없음) | UI 차단은 보조 수단이며, 보안 통제는 서버에 있어야 함 |
| MySQL | — | 실제 MySQL로 enforcement integration 검증 |

---

## 15. production 준비 완료 선언 전 stop condition

아래가 모두 충족되기 전에는 production 준비 완료를 선언하지 않습니다.

1. 14절의 mutation path가 모두 서버 측 gate에 연결되었고, 각 경로마다 RED → GREEN 증거와 bypass 테스트가 있다.
2. SQL_TEXT classifier가 fail-closed(UNKNOWN·PARSE ERROR → DENY)로 구현되었고, arbitrary SELECT, multiple statement,
   CTE+DML, procedure를 다룬다.
3. platform 호출(commit, auto-commit, planner, statement)의 허용 시간 상한과 revoke 지연 정책을 결정하고 검증했다
   (R3, R4).
4. rollback, auto-commit, sever의 `Error` 경로를 테스트했다(R6).
5. 실제 배포 부하에서 metadata capacity와 retry UX를 검증했다(9.1, R13).
6. PostgreSQL metadata의 network partition 상한을 실제 pgjdbc/socket으로 검증했다(R9).
7. MySQL을 지원하려면 실제 MySQL integration 검증을 마쳤다(R10). 그 전에는 allowlist에서 빼는 것을 검토한다.
8. TEMP_WRITE 관리 API가 서버 측 관리자 검증과 함께 존재하고, 일반 사용자의 직접 GraphQL 호출이 거부됨을 증명했다.
   grant·revoke는 그 API에서 `TempWriteMutationCoordinator`를 거쳐 K lock으로 선형화된다(R18, R19).
9. schema v4 업그레이드 전 backup과 복원 절차를 실제로 검증했다(10절).
10. upstream 오류 경로의 SQL·driver detail 노출 정책을 결정했다(R11).

---

> **다시 한 번 — 아직 미결선:**
>
> * 일반 SQL Editor 실행
> * SQL_TEXT classifier와 arbitrary SELECT
> * multiple statements
> * CTE+DML
> * stored procedure / function / anonymous block
> * Data Editor mutation
> * Data Import
> * DDL / Object Editor
> * navigator rename / delete
> * grouping / filter / count의 mutation 가능 경로
> * TEMP_WRITE admin GraphQL API
> * frontend
> * MySQL
>
> `EXPLAIN ANALYZE UPDATE …`를 일반 SQL 실행 API로 보내는 경로는 아직 막히지 않았습니다.
>
> Explain/transaction enforcement spine만 연결됨. 만료는 보수적 margin 기반이며 strict real-time 보장이 아님. 단일
> 프로세스 배포 전제이며 multi-node는 지원하지 않음.
