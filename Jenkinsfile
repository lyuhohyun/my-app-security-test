pipeline {
    agent any 

    environment {
        // 1. 도구 실행 경로 강제 지정 (가장 중요한 수정 포인트)
        // 리눅스 기본 경로(/usr/bin 등)와 사용자 로컬 경로(/home/user/.local/bin)를 모두 포함합니다.
        PATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/home/user/.local/bin:${env.PATH}"
        
        // 2. 결과 파일 및 스크립트 경로 설정
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
                // 취약점이 발견되어도 빌드가 중단되지 않도록 || true를 붙였습니다. 
                // 판단은 마지막 'Risk Engine'이 할 것입니다.
                sh "semgrep scan --config auto --json --output ${SAST_REPORT} . || true"
            }
        }

        stage('Step 3: OSS Scan (Trivy)') {
            steps {
                echo '📦 Trivy를 이용한 오픈소스 취약점 및 SBOM 스캔 시작...'
                // 취약점 점수 데이터를 뽑습니다.
                sh "trivy fs --format json --output ${TRIVY_REPORT} ."
                // 도달성 분석을 위한 SBOM 파일을 생성합니다.
                sh "trivy fs --format cyclonedx --output ${SBOM_REPORT} ."
            }
        }

        stage('Step 4: Risk Engine Analysis') {
            steps {
                echo '🧠 리스크 엔진 가동: 취약점 분석 및 최종 점수 산출 중...'
                // 앞서 추출한 3개의 JSON을 분석하여 8.0점이 넘으면 여기서 빌드가 실패(exit 1)하게 됩니다.
                sh "python3 ${ENGINE_SCRIPT}"
            }
        }
    }

    post {
        always {
            echo '📊 스캔 결과 리포트를 저장하는 중...'
            // 성공/실패 여부와 관계없이 생성된 모든 JSON 파일을 젠킨스 결과창(Artifacts)에 보관합니다.
            archiveArtifacts artifacts: '*.json', allowEmptyArchive: true, fingerprint: true
        }
        success {
            echo '✅ [PASS] 모든 보안 기준을 통과했습니다. 배포 단계로 진행이 가능합니다.'
        }
        failure {
            echo '🚨 [FAIL] 보안 리스크 점수가 기준(8.0)을 초과했거나 시스템 에러가 발생했습니다.'
            echo '상세 내용은 위 로그와 저장된 JSON 리포트를 확인하세요.'
        }
    }
}
