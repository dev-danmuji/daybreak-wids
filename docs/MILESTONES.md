# daybreak-wids 마일스톤 보고

> Development log (Korean) of milestones M0–M9, kept as written at the time. For the current
> state see [README.md](../README.md), [VALIDATION.md](VALIDATION.md) and
> [CHANGELOG.md](../CHANGELOG.md).

기준일 2026-10-05. 기존 코드 없음(빈 디렉터리)에서 시작. 테스트 수는 각 마일스톤 완료 시점의 누적 `pytest` 결과.

| | 범위 | 누적 테스트 |
|---|---|---|
| M0 | 골격, 설정, 모델, SQLite | 88 passed |
| M1 | 센서 탐색, ALFA 감지, 안전 점검 | 134 passed |
| M2 | Kismet REST/Eventbus 연동, replay | 159 passed |
| M3 | 802.11 메타데이터 파서, passive 백엔드, deauth 탐지 | 209 passed |
| M4 | EAPOL 탐지, 상관분석 엔진 | 226 passed |
| M5 | 보호 네트워크 레지스트리, Evil Twin/다운그레이드 | 240 passed |
| M6 | PMF/WPA 점검, 비밀번호 정책 가이드 | 247 passed |
| M7 | 베이스라인, 위험 점수 | 258 passed |
| M8 | 알림 관리자, 로그, 모니터 러너, CLI | 290 passed |
| M9 | 선택 대시보드 + 마무리 리뷰 수정 | 296 passed |

---

## M0 — 골격 / 설정 / 모델 / SQLite

1. **구현**: 패키지 골격(`pyproject.toml`, MIT `LICENSE`, `config.example.yaml`). 엄격한 YAML 로더(알 수 없는 키·타입 오류 거부, 경로는 설정 파일 기준). `safety` 선언(`passive_only: true` 등)이 다르면 시작 거부. 이벤트/Finding/Alert/SecurityProfile 모델, MAC 정규화(대문자 콜론 형식), 메타데이터 allow-list(nonce·MIC·PMKID·key_data·passphrase 등 제거). SQLite 7개 테이블 + `PRAGMA user_version` 기반 마이그레이션(v1 스키마, v2 인덱스, 트랜잭션 롤백).
2. **파일**: `daybreak/{__init__,models,config,safety}.py`, `daybreak/storage/{database,migrations}.py`, `tests/{conftest,test_models,test_config,test_storage}.py`
3. **테스트**: 88 passed. `conftest`가 테스트 중 AF_PACKET 소켓과 `iw/ip/nmcli/notify-send` 실행을 차단.
4. **제한**: 타임스탬프는 epoch REAL 저장(표시는 로컬/ISO 변환).
5. **다음**: M1 센서 탐색.

## M1 — Linux 센서 탐색 / ALFA 감지 / 안전 점검

1. **구현**: sysfs + `iw phy/dev/reg`, `nmcli` 읽기 전용 파싱 → 인터페이스·PHY·드라이버·USB ID·대역(2.4/5/6)·monitor 지원·채널·regdomain·NM 상태. `InterfaceGuard`: 설정된 보호 인터페이스(`wlo1`) + 기본 경로 인터페이스 + 같은 PHY의 인터페이스는 변경 불가, 작업 전후 스냅샷 비교. `SensorController`(monitor 전환/채널 — 센서만, 허용 명령만), `SensorHealthMonitor`(사라짐/같은 MAC 복귀·이름 변경 감지), `sensor check` 진단(NM 충돌 시 원인과 수동 조치만 안내). 정적 안전 테스트(AST): 주입/프레임 생성 라이브러리·raw 소켓 송신·deauth 템플릿·공격 도구·키 유도/MIC 검증·핸드셰이크 export·바이너리 쓰기·패스워드 추측·PSK 입력 옵션 없음, 호스트 명령 allow-list.
2. **파일**: `daybreak/sensor/{discovery,check,control,status}.py`, `tests/{helpers,test_sensor,test_safety}.py`, `tests/fixtures/host/*`(실제 `iw` 출력, SSID/MAC 익명화)
3. **테스트**: 134 passed. 실제 호스트 읽기 전용 확인: `wlx00c0cab85c32 phy3 mt7921u usb 0e8d:7961, 2.4/5/6 GHz, monitor 지원, KR`, `wlo1` 보호·변경 없음, 변경 명령 0건.
4. **제한**: 6 GHz 채널 번호가 2.4 GHz와 겹쳐 레지스트리 채널은 2.4/5 GHz 기준.
5. **다음**: M2 Kismet.

## M2 — Kismet 통합 / Eventbus·API reader

1. **구현**: Kismet 소스로 필드명 검증 후 구현. REST(`/system/status`, `/datasource/all_sources`, `/alerts/definitions`, `/alerts/wrapped/last-time/{ts}`, `/devices/last-time/{ts}`, `/logging/active`), 읽기 전용 엔드포인트 allow-list, `KISMET` 쿠키(readonly API 키)/Basic 인증, 프록시 우회. 장치 레코드는 field simplification `[path, rename]` allow-list로만 요청(핸드셰이크/PMKID/nonce 필드 미요청 + 응답 키 재필터). `crypt_string` + `wpa_mfp_*` → SecurityProfile. Eventbus(websocket-client 선택) ALERT/DATASOURCE_* 구독, 끊기면 REST 폴링. `kismet check`(도달성, 센서 datasource, 요청된 WIDS 알림 정의 여부, 패킷 로그 활성 경고), `kismet config`(source, APSPOOF 규칙, `enable_logging=false` 제안 — 파일은 쓰지 않음). JSONL replay 백엔드.
2. **파일**: `daybreak/sensor/{backend,kismet,replay}.py`, `tests/{kismet_fake,test_kismet}.py`
3. **테스트**: 159 passed (로컬 가짜 Kismet 서버: 인증 실패, 미도달, 중간 다운, datasource 오류, eventbus).
4. **제한**: 실제 Kismet 미설치 환경이라 실제 서버 대상 검증은 못 함. 현재 Kismet master에는 `DISASSOCTRAFFIC` 정의가 없음 → `kismet check`가 경고로 표시(자체 탐지기가 보완).
5. **다음**: M3 deauth.

## M3 — Deauth / Disassoc 탐지

1. **구현**: radiotap(확장 bitmap, FCS 처리, bad-FCS 폐기) + 802.11 관리/데이터 프레임 메타데이터 파서. deauth/disassoc 이유 코드, Protected 비트, 브로드캐스트 BIP(MMIE) 판별. EAPOL은 Key Information 2바이트만 읽어 메시지 번호(1–4) 추론. 수신 전용 `PassiveBackend`(AF_PACKET을 recv만 노출하는 래퍼로 감쌈, monitor 모드 확인, 가드된 채널 호핑), 오프라인 pcap/pcapng 리더. Sliding window/Trigger(히스테리시스). `DeauthDetector`: 버스트(>10/5s), 브로드캐스트 반복, 다수 스테이션, 의심 송신원(RSSI 편차·PMF 필수망의 비보호 프레임·채널 불일치·잘못된 이유 코드), 잘못된 이유 코드. Kismet 알림 → 동일 점수 카테고리 매핑.
2. **파일**: `daybreak/dot11/{ieee80211,frames,rsn}.py`, `daybreak/sensor/{passive,pcapfile}.py`, `daybreak/detectors/{base,window,deauth,kismet_alerts}.py`, `daybreak/registry.py`, `tests/{frames_hex,test_frames,test_deauth}.py`
3. **테스트**: 209 passed (모든 길이로 잘린 프레임에도 예외 없이 처리).
4. **제한**: PMF 보호된 유니캐스트 deauth는 이유 코드가 암호화되어 보이지 않음(정상).
5. **다음**: M4 EAPOL + 상관분석.

## M4 — EAPOL 활동 탐지 / 상관분석 엔진

1. **구현**: `EapolDetector`(스테이션별 핸드셰이크 시작·프레임 수, BSSID별 재인증 스테이션 수·프레임 수, M1 재전송 3초 이내는 1회로 병합). `CorrelationEngine`: BSSID별 incident, 카테고리별 1회 계산(Kismet+자체 탐지 중복 방지), disconnect → 같은 스테이션의 EAPOL 재인증 추적. `POSSIBLE_DEAUTH_ATTACK`, `POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT`(성공 여부를 추정하지 않는다는 문구 포함). 이벤트 단위 일괄 평가, 점수 근거 항상 포함. 파이프라인(중복 억제: 동일 이벤트 + 802.11 retry/seq 재전송, 범위 필터, 저장 버퍼). 합성 fixture 생성기.
2. **파일**: `daybreak/detectors/eapol.py`, `daybreak/correlation/engine.py`, `daybreak/pipeline.py`, `tests/fixtures/{make_fixtures.py,*.jsonl}`, `tests/test_correlation.py`
3. **테스트**: 226 passed. 수정한 버그: 초기 접속 EAPOL이 나중 deauth와 묶이던 순서 문제(EAPOL 증거는 disconnect 이후만 인정).
4. **제한**: Kismet 단독 모드(frame tap 없음)에서는 EAPOL 기반 상관분석 불가.
5. **다음**: M5 레지스트리 + Evil Twin.

## M5 — 보호 네트워크 레지스트리 / Evil Twin·다운그레이드 탐지

1. **구현**: `network add/remove`용 별도 레지스트리 파일(`networks.yaml`; config.yaml 주석 보존, config 정의 네트워크는 CLI로 수정 불가). BSSID 없는 네트워크는 `unconfigured`, 주변 AP 자동 편입 없음(후보로만 표시). `SpoofDetector`: `UNKNOWN_BSSID_FOR_PROTECTED_SSID`(경고), WPA3→WPA2 다운그레이드, 암호화 변경, PMF 소실, 채널 이상, 비호환 중복 SSID, 같은 BSSID의 프로파일 교대(BSSID 복제 의심). 기준: 레지스트리 기대치 → 베이스라인 → 등록 BSSID 관측값. IE/Kismet 출처 차이 무시 비교(오탐 방지). `POSSIBLE_EVIL_TWIN`은 미등록 BSSID 자체의 약화된 보안이 있을 때만.
2. **파일**: `daybreak/detectors/spoof.py`, `daybreak/registry.py`, `daybreak/models.py`(signature), `tests/test_spoof.py`
3. **테스트**: 240 passed. 수정: 한 비콘에서 같은 카테고리가 두 경로로 중복 보고되던 문제, 한 이벤트의 여러 finding으로 복합 경보가 3번 에스컬레이션되던 문제.
4. **제한**: 사용자의 메시/익스텐더가 미등록이면 LOW 경고가 뜸(힌트로 등록 방법 안내).
5. **다음**: M6 감사.

## M6 — PMF / WPA 설정 점검, 비밀번호 정책

1. **구현**: 비콘/Kismet 레코드 기반 감사: OPEN/WEP/WPA(TKIP)/WPA2-PSK/전환 모드/WPA3-SAE/Enterprise/OWE, PMF disabled/capable/required, SAE-H2E, WPS 광고, 약한 암호, 라디오 간 불일치, 미등록 BSSID. 명세 예시 형식 출력 + 권고(AP 설정은 절대 변경하지 않음). 비밀번호 정책 체크리스트(WPA3, PMF, 길고 무작위한 패스프레이즈, 공유기 기본 비밀번호, 관리자 계정, WPS 비활성화, 게스트 분리) — PSK 입력 경로 없음, 관측 가능한 항목만 표시.
2. **파일**: `daybreak/detectors/security.py`, `daybreak/policy.py`, `tests/test_audit.py`
3. **테스트**: 247 passed.
4. **제한**: WPS 상태는 비콘의 WPS IE 존재 여부만 판단(Kismet 출처는 `wps_state` 값이 있을 때만).
5. **다음**: M7 베이스라인.

## M7 — 베이스라인 엔진 / 위험 점수

1. **구현**: 분 단위 disconnect/EAPOL/(재)연결 비율(중앙값·MAD·p95·최대), 등록 BSSID·채널·보안 프로파일·BSSID별 RSSI·클라이언트 수 범위를 SQLite에 저장(네트워크별 활성 1개). 편차 = 견고 z-score(중앙값/MAD, 최소 sigma) AND 학습 최대치 초과 AND 최소 건수 → `BASELINE_DEVIATION`. 베이스라인 RSSI/보안/채널을 의심 송신원·다운그레이드·채널 이상 판단에 사용. 위험 점수 헬퍼(`Risk N SEVERITY` + 근거 줄), threat level.
2. **파일**: `daybreak/baseline/engine.py`, `daybreak/scoring.py`, `tests/test_baseline.py`
3. **테스트**: 258 passed (고정 임계값 미만이지만 평소 대비 큰 deauth 비율 탐지 포함).
4. **제한**: 공격 중 학습하면 기준이 오염될 수 있음(견고 통계로 완화; 공격 없는 구간에서 학습 권장).
5. **다음**: M8 알림/CLI.

## M8 — 알림 관리자 / 로그 / CLI / 보고서

1. **구현**: Notifier 인터페이스 + 레지스트리(Slack/Discord/Telegram/email/webhook 확장 지점), console/JSONL/desktop(`notify-send`). cooldown(유형+네트워크 키, 점수 +10 또는 심각도 상승 시 돌파, 억제 건수 기록), 사람용 채널 분당 rate limit. 사람이 읽는 로그·JSONL 모두 크기 기반 회전. 모니터 러너: Kismet 우선 → 실패 시 passive 폴백, 백엔드 재시도(지수 백오프), `SENSOR_LOST`/`SENSOR_RECOVERED`(sysfs + Kismet datasource), 복구 시 센서만 monitor 재설정(`auto_prepare`), 상태 파일. CLI: `sensor list/check/prepare/release`, `kismet check/config`, `monitor start/status`, `network list/add/remove`, `baseline create/show`, `alerts`, `report`, `audit security/policy`, 전역 `--dry-run`/`--json`.
2. **파일**: `daybreak/alerts/{base,manager,console,jsonl,desktop,formatting}.py`, `daybreak/{runtime,monitor,report,cli}.py`, `daybreak/sensor/select.py`, `tests/{test_alerts,test_monitor,test_cli}.py`
3. **테스트**: 290 passed. 실제 호스트: `monitor start --duration 4` → Kismet 미도달 → passive 폴백 → "monitor 모드 아님, `sudo daybreak-wids sensor prepare --apply`" 안내 → 종료 후 "protected interfaces unchanged", `wlo1` 연결 유지.
4. **제한**: root로 실행하면 데스크톱 알림이 사용자 세션에 닿지 않는 경우가 많음. 같은 사용자로 일관되게 실행해야 DB 권한 문제가 없음.
5. **다음**: M9 대시보드.

## M9 — 선택 대시보드 + 최종 점검

1. **구현**: FastAPI 읽기 전용 API(`/api/status|networks|alerts|timeline|baseline`) + 정적 UI(Sensor, Protected Networks, Current Alerts, Event Timeline, AP Security, Baseline, Threat Level, Last 5 min). 기본 127.0.0.1 바인딩(비루프백은 `allow_remote` 필요), 비루프백 Host 헤더 거부(DNS rebinding), GET 외 405, 엄격한 CSP, 외부 리소스 없음, 모든 데이터는 `textContent`로 삽입(SSID XSS 방지). 마무리 리뷰 수정: Kismet 재연결 시 eventbus 스레드 누수, 장치 커서 선행 갱신, 센서 부재 시 메시지.
2. **파일**: `daybreak/dashboard/{app.py,static/*}`, `tests/test_dashboard.py`, `README.md`, `.gitignore`, `docs/MILESTONES.md`
3. **테스트**: 296 passed. 실제 서버 기동 확인: 악성 Host 400, POST 405.
4. **제한**: 브라우저 렌더링은 이 환경에서 확인하지 못함(API/정적 파일 응답만 검증).
5. **다음**: 실제 하드웨어 검증 — 아래 참조.

---

## Definition of Done 점검

| 항목 | 상태 |
|---|---|
| ALFA MT7921U를 passive sensor로 사용 | 코드 경로 완성(Kismet/passive). **실제 monitor 모드 캡처는 미실행**(root 필요) |
| `wlo1` 인터넷 연결 영향 없음 | 가드 + 전후 스냅샷 검증, 실제 호스트에서 확인 |
| protected AP 설정 | `network add/list/remove`, config |
| deauth/disassoc burst 탐지 | ✓ (`deauth_burst.jsonl`) |
| EAPOL 재인증 증가 탐지 | ✓ |
| 두 이벤트 상관분석 | ✓ (`handshake_pattern.jsonl`) |
| evil twin / 다운그레이드 징후 | ✓ (`evil_twin.jsonl`) |
| WPA/PMF 방어 상태 점검 | ✓ `audit security` |
| SQLite + JSONL 기록 | ✓ |
| alert cooldown | ✓ |
| synthetic fixture 재현 | ✓ |
| pytest green | ✓ 296 passed |
| 공격/주입/크래킹 기능 없음 | ✓ 정적 안전 테스트 |

## 실제 하드웨어 검증 절차(사용자 실행)

v0.1.0 기준 절차는 [README.md](../README.md)의 *Kismet backend* / *Passive backend* 절과
[VALIDATION.md](VALIDATION.md)에 있다. `sudo`는 `PATH`와 `HOME`을 초기화하므로 venv의 실행
파일을 직접 지정하고 `-c`를 항상 준다. passive 경로는 안내 스크립트로 실행한다.

```bash
scripts/hardware-smoke-test.sh discover   # SSID만 등록된 네트워크의 BSSID 후보 확인(자동 채택 없음)
scripts/hardware-smoke-test.sh run        # 사전 점검 → 센서 준비 → passive 관찰 → 해제, wlo1 불변 검증
```
