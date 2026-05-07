import json
import os
import sys  # 젠킨스 종료 코드를 위해 추가

def load_json(filepath):
    """JSON 파일을 안전하게 읽어오는 함수"""
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    else:
        print(f"[-] 에러: {filepath} 파일이 없습니다. 스캔이 정상적으로 완료되었는지 확인하세요.")
        return None

def main():
    print("🚀 리스크 엔진 가동을 시작합니다...\n")

    # 1. 3대 핵심 데이터 로드
    sast_data = load_json('sast-result.json')
    trivy_data = load_json('trivy-result.json')
    sbom_data = load_json('sbom.json')

    if not all([sast_data, trivy_data, sbom_data]):
        print("❌ 데이터가 부족하여 엔진을 가동할 수 없습니다. 빌드를 중단합니다.")
        sys.exit(1) # 파일이 없으면 젠킨스 빌드 실패 처리

    # 2. 비즈니스 중요도 산출 (AST 데이터 활용)
    print("🔍 1단계: AST 비즈니스 중요도 분석 중...")
    business_weight = 0.5  # 기본값 (보통)
    
    # Semgrep 결과에 치명적인(ERROR) 취약점이 있다면 가중치 극대화
    for result in sast_data.get('results', []):
        if result.get('extra', {}).get('severity') == 'ERROR':
            business_weight = 1.0
            print("  ⚠️ 코드 내 심각한 취약점(ERROR) 발견! 비즈니스 가중치를 최고(1.0)로 설정합니다.")
            break
    print(f"  👉 현재 시스템의 비즈니스 가중치: {business_weight}\n")

    # 3. 오픈소스 취약점 분석 및 최종 리스크 계산
    print("🔍 2단계: 오픈소스 취약점 분석 및 최종 점수 산출 중...\n")
    
    max_score = 0.0  # 이번 빌드에서 발견된 가장 높은 리스크 점수를 기록할 변수
    
    # Trivy 결과 파싱
    if 'Results' in trivy_data:
        for target in trivy_data['Results']:
            if 'Vulnerabilities' in target:
                for vuln in target['Vulnerabilities']:
                    vuln_id = vuln.get('VulnerabilityID', 'Unknown')
                    pkg_name = vuln.get('PkgName', 'Unknown')
                    
                    # [Trivy] CVSS 기본 점수 추출
                    cvss_score = 0.0
                    cvss_data = vuln.get('CVSS', {}).get('nvd', {})
                    if cvss_data:
                        cvss_score = cvss_data.get('V3Score', 0.0)
                    
                    if cvss_score == 0:
                        continue # 점수가 없는 데이터는 계산에서 제외

                    # 4. SBOM 도달성 확인 (현재는 하드코딩된 예시, 추후 파싱 로직 추가 가능)
                    reachability_weight = 0.8
                    
                    # 5. 🔥 엔진 공식 적용: 최종 리스크 점수 계산
                    final_risk_score = cvss_score * business_weight * reachability_weight
                    
                    # 최고 점수 갱신 (가장 위험한 놈을 찾기 위해)
                    if final_risk_score > max_score:
                        max_score = final_risk_score
                    
                    # 최종 점수가 7.0 이상인 위험한 녀석들만 터미널/젠킨스 로그에 출력
                    if final_risk_score >= 7.0:
                        print("-" * 50)
                        print(f"🚨 [위험 감지] {pkg_name} 라이브러리 ({vuln_id})")
                        print(f"   • 기본 파괴력 (CVSS)   : {cvss_score} 점")
                        print(f"   • 중요도/도달성 보정치 : x {business_weight} / x {reachability_weight}")
                        print(f"   ▶️ 산출된 리스크 점수  : {round(final_risk_score, 1)} / 10.0 점")

    print("-" * 50)
    
    # 6. 최종 젠킨스 빌드 성공/실패 결정 로직
    print(f"\n📊 이번 빌드의 최고 리스크 점수: {round(max_score, 1)} 점")
    
    if max_score >= 8.0:
        print("❌ [BUILD FAILED] 8.0점 이상의 치명적인 리스크가 존재합니다.")
        print("   -> 젠킨스 파이프라인을 강제 중단합니다. 담당자는 즉시 취약점을 패치하세요.")
        sys.exit(1)  # 젠킨스에게 "실패" 신호를 보냄
    else:
        print("✅ [BUILD SUCCESS] 모든 보안 게이트를 안전하게 통과했습니다.")
        sys.exit(0)  # 젠킨스에게 "성공" 신호를 보냄

if __name__ == "__main__":
    main()
