pipeline {
    agent any 

    environment {
        // 결과 파일 및 스크립트 파일명 설정
        SAST_REPORT = "sast-result.json"
        TRIVY_REPORT = "trivy-result.json"
        SBOM_REPORT = "sbom.json"
        ENGINE_SCRIPT = "risk_engine.py"
    }

    stages {
        stage('Step 1: Checkout') {
            steps {
                echo '📥 GitHub에서 최신 소스 코드를 가져오는 중...'
                checkout scm
            }
        }

        stage('Step 2: AST Scan (Semgrep)') {
            steps {
                echo '🔍 Semgrep을 이용한 소스 코드 보안 스캔 시작...'
                // 확인해주신 semgrep 절대 경로 적용
                sh "/home/user/.local/bin/semgrep scan --config auto --json --output ${SAST_REPORT} . || true"
            }
        }

        stage('Step 3: OSS Scan (Trivy)') {
            steps {
                echo '📦 Trivy를 이용한 오픈소스 취약점 및 SBOM 스캔 시작...'
                // 확인해주신 trivy 절대 경로 적용
                sh "/usr/bin/trivy fs --format json --output ${TRIVY_REPORT} ."
                sh "/usr/bin/trivy fs --format cyclonedx --output ${SBOM_REPORT} ."
            }
        }

        stage('Step 4: Risk Engine Analysis') {
            steps {
                echo '🧠 리스크 엔진 가동: 취약점 분석 및 최종 점수 산출 중...'
                // 파이썬으로 리스크 엔진 스크립트 실행
                sh "python3 ${ENGINE_SCRIPT}"
            }
        }
    }

    post {
        always {
            echo '📊 스캔 결과 리포트를 저장하는 중...'
            // 빌드 성공 여부와 상관없이 JSON 파일들을 젠킨스에 저장
            archiveArtifacts artifacts: '*.json', allowEmptyArchive: true, fingerprint: true
        }
        success {
            echo '✅ [PASS] 모든 보안 기준을 통과했습니다. 배포 단계로 진행이 가능합니다.'
        }
        failure {
            echo '🚨 [FAIL] 보안 리스크 점수가 기준(8.0)을 초과했거나 스크립트 에러가 발생했습니다.'
            echo '상세 내용은 위 로그와 저장된 JSON 리포트를 확인하세요.'
        }
    }
}
