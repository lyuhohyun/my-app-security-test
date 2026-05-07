pipeline {
    agent any 

    environment {
        SAST_REPORT = "sast-result.json"
        // 🔥 범인 검거! TRIVY_ 라는 접두사를 지우고 VULN_ 으로 바꿨습니다.
        VULN_REPORT = "trivy-result.json" 
        SBOM_REPORT = "sbom.json"
        ENGINE_SCRIPT = "risk_engine.py"
    }

    stages {
        stage('Step 1: Checkout') {
            steps {
                echo '📥 GitHub에서 소스 코드를 가져오는 중...'
                checkout scm
            }
        }

        stage('Step 2: AST Scan (Semgrep)') {
            steps {
                echo '🔍 Semgrep 스캔...'
                sh "semgrep scan --config auto --json --output ${SAST_REPORT} . || true"
            }
        }

        stage('Step 3: OSS Scan (Trivy)') {
            steps {
                echo '📦 Trivy 포터블 버전 다운로드 및 독립 스캔 시작...'
                sh '''
                curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b .
                # 아래 변수명도 VULN_REPORT로 수정됨!
                ./trivy fs --format json --output ${VULN_REPORT} .
                ./trivy fs --format cyclonedx --output ${SBOM_REPORT} .
                '''
            }
        }

        stage('Step 4: Risk Engine Analysis') {
            steps {
                echo '🧠 리스크 엔진 분석 시작...'
                sh '''
                if command -v python3 &>/dev/null; then
                    python3 ${ENGINE_SCRIPT}
                else
                    python ${ENGINE_SCRIPT}
                fi
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '*.json', allowEmptyArchive: true, fingerprint: true
        }
        success {
            echo '✅ [PASS] 모든 보안 기준을 통과했습니다!'
        }
        failure {
            echo '🚨 [FAIL] 보안 리스크 점수 초과 또는 에러 발생!'
        }
    }
}
