import json
import sys
import os
import urllib.request

# 1. 설정값 (Jenkinsfile에 지정한 파일명과 동일해야 합니다)
SAST_REPORT = "sast-result.json"
TRIVY_REPORT = "trivy-result.json"
RISK_THRESHOLD = 8.0  # 빌드 차단 기준 점수

def calculate_sast_score():
    """Semgrep SAST 취약점 점수 계산 (ERROR: 1점, WARNING: 0.5점)"""
    score = 0.0
    if not os.path.exists(SAST_REPORT):
        return score
        
    try:
        with open(SAST_REPORT, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for result in data.get('results', []):
                severity = result.get('extra', {}).get('severity', '').upper()
                if severity == 'ERROR':
                    score += 1.0
                elif severity == 'WARNING':
                    score += 0.5
    except Exception as e:
        print(f"[-] SAST 리포트 분석 중 에러 발생: {e}")
    return score

def calculate_trivy_score():
    """Trivy 오픈소스 취약점 점수 계산 (CRITICAL: 2점, HIGH: 1점, MEDIUM: 0.5점)"""
    score = 0.0
    if not os.path.exists(TRIVY_REPORT):
        return score
        
    try:
        with open(TRIVY_REPORT, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for result in data.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    severity = vuln.get('Severity', '').upper()
                    if severity == 'CRITICAL':
                        score += 2.0
                    elif severity == 'HIGH':
                        score += 1.0
                    elif severity == 'MEDIUM':
                        score += 0.5
    except Exception as e:
        print(f"[-] Trivy 리포트 분석 중 에러 발생: {e}")
    return score

def main():
    print("🚀 보안 리스크 엔진 가동 시작...")
    
    # 점수 계산
    sast_score = calculate_sast_score()
    trivy_score = calculate_trivy_score()
    final_score = sast_score + trivy_score
    
    print(f"📊 Semgrep 코드 취약점 점수: {sast_score}")
    print(f"📦 Trivy 오픈소스 취약점 점수: {trivy_score}")
    print(f"🔥 최종 리스크 점수: {final_score}")

    # ========================================================
    # 그라파나 시각화를 위한 Prometheus Pushgateway로 데이터 전송
    # ========================================================
    try:
        # 🔥 알려주신 진짜 서버 IP(192.168.0.143)로 Pushgateway(9091포트)에 쏩니다!
        pushgateway_url = "http://192.168.0.143:9091/metrics/job/security_scan"
        metric_data = f"security_risk_score {final_score}\n".encode('utf-8')
        
        req = urllib.request.Request(pushgateway_url, data=metric_data, method='POST')
        urllib.request.urlopen(req, timeout=5)
        print("✅ Grafana(Pushgateway)로 점수 전송 완료!")
    except Exception as e:
        print(f"⚠️ 점수 전송 실패 (파이프라인은 계속 진행됩니다): {e}")
    # ========================================================

    # 최종 패스/차단 판정
    print("-" * 40)
    if final_score > RISK_THRESHOLD:
        print(f"🚨 [FAIL] 위험! 최종 점수({final_score})가 기준치({RISK_THRESHOLD})를 초과했습니다.")
        sys.exit(1)  # 젠킨스 빌드를 실패(빨간불)로 만듦
    else:
        print(f"✅ [PASS] 안전! 최종 점수({final_score})가 기준치({RISK_THRESHOLD}) 이하입니다.")
        sys.exit(0)  # 젠킨스 빌드를 성공(초록불)으로 만듦

if __name__ == "__main__":
    main()
