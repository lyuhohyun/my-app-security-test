pipeline {
    agent any 

    environment {
        // 1. 도구 실행 경로 지정 (Path)
        // 아까 pipx로 설치한 semgrep이 /home/user/.local/bin 에 있으므로 젠킨스가 찾을 수 있게 추가합니다.
        PATH = "/home/user/.local/bin:/usr/local/bin:/usr/bin:/bin:${env.PATH}"
        
        // 2. 작업 파일 경로 지정 (Workspace 기반 상대 경로)
        SAST_REPORT = "./sast-result.json"
        TRIVY_REPORT = "./trivy-result.json"
        SBOM_REPORT = "./sbom.json"
        ENGINE_SCRIPT = "./risk_engine.py" // 파이썬 스크립트 위치
    }

    stages {
        stage('Step 1: Checkout') {
            steps {
                // Git 저장소에서 소스코드와 risk_engine.py를 젠킨스 워크스페이스로 가져옵니다.
                checkout scm 
            }
        }

        stage('Step 2: AST Scan (Semgrep)') {
            steps {
                echo 'Running Semgrep...'
                // 현재 폴더(.)를 스캔하고, 지정한 경로에 JSON을 저장합니다.
                // || true 를 붙여서 스캔 중 취약점이 나와도 파이프라인이 멈추지 않고 다음 단계로 넘어가게 합니다.
                sh "semgrep scan --config auto --json --output ${SAST_REPORT} . || true"
            }
        }

        stage('Step 3: OSS Scan (Trivy)') {
            steps {
                echo 'Running Trivy Vulnerability & SBOM Scan...'
                sh "trivy fs --format json --output ${TRIVY_REPORT} ."
                sh "trivy fs --format cyclonedx --output ${SBOM_REPORT} ."
            }
        }

        stage('Step 4: Risk Engine Analysis') {
            steps {
                echo 'Calculating Final Risk Score...'
                // 앞서 만든 파이썬 스크립트를 실행합니다. 
                // 이 스크립트가 sys.exit(1)을 뱉으면 여기서 빌드가 FAILED 처리됩니다.
                sh "python3 ${ENGINE_SCRIPT}"
            }
        }
    }

    post {
        always {
            // 빌드 성공/실패 여부와 상관없이 3개의 JSON 결과물을 젠킨스 대시보드에 파일로 저장합니다.
            archiveArtifacts artifacts: '*.json', allowEmptyArchive: true, fingerprint: true
        }
        success {
            echo '✅ [성공] 모든 보안 검증을 통과하여 배포를 계속 진행합니다.'
        }
        failure {
            echo '🚨 [실패] 보안 리스크 점수가 기준(8.0)을 초과하여 파이프라인이 차단되었습니다.'
        }
    }
}
