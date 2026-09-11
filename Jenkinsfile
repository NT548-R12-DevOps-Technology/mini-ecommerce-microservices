/*
 * Dynamic Jenkins pipeline for a monorepo microservices setup.
 * Add a new service by appending one line in getServiceMatrix().
 */

def getServiceMatrix() {
    return [
        [name: 'api-gateway',    dir: 'api-gateway',   flag: 'BUILD_API_GATEWAY',  image: 'api-gateway'],
        [name: 'user-service',   dir: 'user-service',  flag: 'BUILD_USER_SERVICE', image: 'user-service'],
        [name: 'product-service',dir: 'product-service', flag: 'BUILD_PRODUCT',    image: 'product-service'],
        [name: 'inventory-service', dir: 'inventory-service', flag: 'BUILD_INVENTORY', image: 'inventory-service'],
        [name: 'payment-service', dir: 'payment-service', flag: 'BUILD_PAYMENT', image: 'payment-service'],
        [name: 'order-service',  dir: 'order-service', flag: 'BUILD_ORDER',        image: 'order-service'],
        [name: 'frontend',       dir: 'front-end',     flag: 'BUILD_FRONTEND',     image: 'frontend']
    ]
}

def getEnvFlag(String name) {
    def value = env.getProperty(name)
    return value ? value : 'false'
}

def setEnvFlag(String name, String value) {
    env.setProperty(name, value)
}

def buildServices() {
    return getServiceMatrix().findAll { service -> getEnvFlag(service.flag) == 'true' }
}

def anyServiceBuildEnabled() {
    return getServiceMatrix().any { service -> getEnvFlag(service.flag) == 'true' }
}

def imageRef(Map service) {
    return "${env.DOCKERHUB_USER}/${env.PROJECT}-${service.image}:${env.IMAGE_TAG}"
}

def detectTestImage(Map service) {
    return sh(
        returnStdout: true,
        script: """awk 'toupper(\$1) == "FROM" { for (i = 2; i <= NF; i++) if (\$i !~ /^--/) { print \$i; exit } }' "${service.dir}/Dockerfile" """
    ).trim()
}

def runServiceTest(Map service) {
    def testImage = detectTestImage(service)

    switch (service.name) {
        case 'api-gateway':
        case 'product-service':
        case 'payment-service':
        case 'order-service':
            sh """
              mkdir -p "\$HOME/.m2"
              docker run --rm \\
                -v "\$PWD/${service.dir}:/app" \\
                -v "\$HOME/.m2:/root/.m2" \\
                -w /app \\
                ${testImage} \\
                mvn -B clean test
            """
            break

        case 'user-service':
        case 'inventory-service':
            sh """
              mkdir -p "\$HOME/go/pkg/mod"
              docker run --rm \\
                -v "\$PWD/${service.dir}:/app" \\
                -v "\$HOME/go/pkg/mod:/go/pkg/mod" \\
                -w /app \\
                ${testImage} \\
                sh -c "go test ./..."
            """
            break

        case 'frontend':
            sh """
              mkdir -p "\$HOME/.npm"
              docker run --rm \\
                -v "\$PWD/${service.dir}:/app" \\
                -v "\$HOME/.npm:/root/.npm" \\
                -w /app \\
                ${testImage} \\
                sh -c "npm ci && npm run build"
            """
            break

        default:
            error "No test command configured for service: ${service.name}"
    }
}

def dependencyScanConfig(Map service) {
    switch (service.name) {
        case 'api-gateway':
        case 'product-service':
        case 'payment-service':
        case 'order-service':
            return [
                image: 'maven:3.9.6-eclipse-temurin-17',
                manifest: 'pom.xml',
                cacheSetup: "mkdir -p \"${env.HOME}/.m2\"",
                cacheMount: "-v \"${env.HOME}/.m2:/root/.m2\""
            ]

        case 'user-service':
        case 'inventory-service':
            return [
                image: 'golang:1.25.8-bookworm',
                manifest: 'go.mod',
                cacheSetup: "mkdir -p \"${env.HOME}/go/pkg/mod\"",
                cacheMount: "-v \"${env.HOME}/go/pkg/mod:/go/pkg/mod\""
            ]

        case 'frontend':
            return [
                image: 'node:20-bookworm',
                manifest: 'package.json',
                cacheSetup: "mkdir -p \"${env.HOME}/.npm\"",
                cacheMount: "-v \"${env.HOME}/.npm:/root/.npm\""
            ]

        default:
            error "No dependency scan configuration for service: ${service.name}"
    }
}

def runSnykDependencyScan(Map service) {
    def config = dependencyScanConfig(service)
    def projectName = "${env.PROJECT}-${service.dir}-dependencies"
    def targetReference = env.BRANCH_NAME ?: 'main'

    withCredentials([
        string(
            credentialsId: 'snyk-token',
            variable: 'SNYK_TOKEN'
        )
    ]) {
        sh """
          set +e
          ${config.cacheSetup}

          run_snyk() {
            docker run --rm \\
              --entrypoint /usr/local/bin/snyk \\
              -e SNYK_TOKEN \\
              -v /usr/local/bin/snyk:/usr/local/bin/snyk:ro \\
              -v \"${env.WORKSPACE}/${service.dir}:/app\" \\
              ${config.cacheMount} \\
              -w /app \\
              ${config.image} \\
              \"\$@\"
          }

          run_snyk test \\
            --file=\"${config.manifest}\" \\
            --severity-threshold=\"${env.SNYK_SEVERITY}\"
          SNYK_STATUS=\$?

          run_snyk monitor \\
            --file=\"${config.manifest}\" \\
            --project-name=\"${projectName}\" \\
            --target-reference=\"${targetReference}\" || true

          exit \$SNYK_STATUS
        """
    }
}

def runSonarAnalysis(Map service) {
    def projectKey = "${env.PROJECT}-${service.dir}"
    def javaBinariesArg = [
        'api-gateway',
        'product-service',
        'payment-service',
        'order-service'
    ].contains(service.name) ? '-Dsonar.java.binaries=target/classes' : ''

    lock(resource: 'sonarqube-analysis') {
        withCredentials([
            string(
                credentialsId: 'sonarqube-token',
                variable: 'SONAR_TOKEN'
            )
        ]) {
            sh """
              docker run --rm \\
                -e SONAR_HOST_URL \\
                -e SONAR_TOKEN \\
                -e SONAR_USER_HOME=/tmp/.sonar \\
                -v \"${env.WORKSPACE}/${service.dir}:/usr/src:ro\" \\
                ${env.SONAR_SCANNER_IMAGE} \\
                -Dsonar.projectKey=\"${projectKey}\" \\
                -Dsonar.projectName=\"${projectKey}\" \\
                -Dsonar.projectVersion=\"${env.IMAGE_TAG}\" \\
                -Dsonar.sources=. \\
                -Dsonar.sourceEncoding=UTF-8 \\
                -Dsonar.exclusions=\"target/**,node_modules/**,dist/**,build/**\" \\
                -Dsonar.working.directory=/tmp/.scannerwork \\
                -Dsonar.qualitygate.wait=true \\
                -Dsonar.qualitygate.timeout=\"${env.SONAR_QUALITY_GATE_TIMEOUT}\" \\
                ${javaBinariesArg}
            """
        }
    }
}

def runParallelForSelected(String stagePrefix, Closure worker) {
    def tasks = [:]

    buildServices().each { svc ->
        def service = svc
        tasks["${stagePrefix} ${service.name}"] = {
            worker(service)
        }
    }

    if (tasks.isEmpty()) {
        echo "No services selected for ${stagePrefix.toLowerCase()}."
        return
    }

    parallel tasks
}

def updateGitOpsImageTag(Map service) {
    sh """
      yq e -i '.images[] |= (select(.name == "${env.DOCKERHUB_USER}/${env.PROJECT}-${service.image}").newTag = "${env.IMAGE_TAG}")' \\
      overlays/dev/kustomization.yaml
    """
}

def cleanupBuiltImages() {
    def images = buildServices().collect { service -> imageRef(service) }

    if (images.isEmpty()) {
        echo 'No built images to clean up.'
    } else {
        images.each { img ->
            sh "docker image rm -f ${img} || true"
        }
    }

    // Remove dangling layers and older resources to keep Jenkins workers clean.
    sh 'docker image prune -f || true'
    sh 'docker system prune -f --filter "until=24h" || true'
}

pipeline {
    agent any

    options {
        timestamps()
        ansiColor('xterm')
    }

    environment {
        DOCKERHUB_USER = "tienphatng237"
        PROJECT        = "mini-ecommerce"
        IMAGE_TAG      = "${env.GIT_COMMIT.take(7)}"

        GITOPS_REPO = "https://github.com/NT114-Q21-Specialized-Project/kubernetes-hub.git"
        GITOPS_DIR  = "kubernetes-hub"

        TRIVY_SEVERITY       = "HIGH,CRITICAL"
        TRIVY_SOURCE_SEVERITY = "MEDIUM,HIGH,CRITICAL"
        TRIVY_EXIT_CODE      = "1"
        TRIVY_CACHE_DIR      = "${HOME}/.trivy-cache-mini-ecommerce"
        SNYK_SEVERITY        = "high"

        SONAR_HOST_URL            = "http://10.0.23.10:9000"
        SONAR_SCANNER_IMAGE       = "sonarsource/sonar-scanner-cli:12.1.0.3233_8.0.1"
        SONAR_QUALITY_GATE_TIMEOUT = "300"
    }

    stages {

        /* =========================
           CHECKOUT APP REPO
        ========================= */
        stage('Checkout App Repo') {
            steps {
                checkout scm
            }
        }

        stage('Pipeline Context') {
            steps {
                sh '''
                  echo "Branch   : ${BRANCH_NAME:-unknown}"
                  echo "Commit   : ${GIT_COMMIT:-unknown}"
                  echo "Build URL: ${BUILD_URL:-n/a}"
                '''
            }
        }

        /* =========================
           DETECT CHANGED SERVICES
        ========================= */
        stage('Detect Changed Services') {
            steps {
                script {
                    sh 'git fetch --no-tags --depth=100 origin +refs/heads/main:refs/remotes/origin/main || true'

                    def changedFilesRaw = sh(
                        script: '''
                          set +e

                          CHANGED_FILES="$(git diff --name-only origin/main...HEAD || true)"

                          # On main branch, HEAD is usually equal to origin/main after push,
                          # so triple-dot diff can be empty even when this commit changed files.
                          # Fallback to previous build commit range for incremental CI on main.
                          if [ -z "$CHANGED_FILES" ] && [ "${BRANCH_NAME:-}" = "main" ]; then
                            PREV_COMMIT="${GIT_PREVIOUS_SUCCESSFUL_COMMIT:-${GIT_PREVIOUS_COMMIT:-HEAD~1}}"
                            if git rev-parse --verify "$PREV_COMMIT" >/dev/null 2>&1; then
                              CHANGED_FILES="$(git diff --name-only "$PREV_COMMIT" HEAD || true)"
                            fi
                          fi

                          # Fallback for shallow checkouts where previous commit is unavailable.
                          if [ -z "$CHANGED_FILES" ]; then
                            CHANGED_FILES="$(git show --pretty='' --name-only HEAD || true)"
                          fi

                          printf "%s" "$CHANGED_FILES"
                        ''',
                        returnStdout: true
                    ).trim()

                    def changedFiles = changedFilesRaw ? changedFilesRaw.split('\n') : []
                    def isCiChange = changedFiles.any { it == 'Jenkinsfile' }

                    echo 'Changed files:'
                    changedFiles.each { echo " - ${it}" }

                    // Set build flags dynamically from the service matrix.
                    getServiceMatrix().each { service ->
                        def shouldBuild = changedFiles.any { it.startsWith("${service.dir}/") } ? 'true' : 'false'
                        setEnvFlag(service.flag, shouldBuild)
                    }

                    setEnvFlag('BUILD_CONTRACTS', changedFiles.any { it.startsWith('api-contracts/') } ? 'true' : 'false')

                    // If CI config changed, force rebuild/retest all services.
                    if (isCiChange) {
                        echo 'Jenkinsfile changed -> rebuild all services'
                        getServiceMatrix().each { service ->
                            setEnvFlag(service.flag, 'true')
                        }
                        setEnvFlag('BUILD_CONTRACTS', 'true')
                    }

                    echo '================= CHANGE SUMMARY ================='
                    echo "Jenkinsfile   : ${isCiChange}"
                    getServiceMatrix().each { service ->
                        echo String.format('%-18s : %s', service.name, getEnvFlag(service.flag))
                    }
                    echo "contracts    : ${getEnvFlag('BUILD_CONTRACTS')}"
                    echo '=================================================='
                }
            }
        }

        stage('Contract Validation') {
            when {
                expression {
                    env.BUILD_CONTRACTS == 'true' || anyServiceBuildEnabled()
                }
            }
            steps {
                sh '''
                  set -e

                  if [ ! -d "api-contracts" ]; then
                    echo "api-contracts directory not found"
                    exit 1
                  fi

                  for spec in api-contracts/*.openapi.yaml; do
                    [ -f "$spec" ] || continue
                    echo "Validating contract: $spec"
                    mkdir -p "$HOME/.npm"
                    docker run --rm \
                      -v "$PWD:/work" \
                      -v "$HOME/.npm:/root/.npm" \
                      -w /work \
                      node:20-alpine \
                      sh -c "npx --yes @apidevtools/swagger-cli@4.0.4 validate $spec"
                  done
                '''
            }
        }

        /* =========================
           PREPARE GITOPS REPO (ONCE)
        ========================= */
        stage('Prepare GitOps Repo') {
            when {
                expression { anyServiceBuildEnabled() }
            }
            steps {
                withCredentials([
                    usernamePassword(
                        credentialsId: 'github-token',
                        usernameVariable: 'GIT_USER',
                        passwordVariable: 'GIT_TOKEN'
                    )
                ]) {
                    script {
                        sh '''
                          rm -rf "${GITOPS_DIR}"
                          REPO_NO_PROTO="${GITOPS_REPO#https://}"
                          git clone "https://${GIT_USER}:${GIT_TOKEN}@${REPO_NO_PROTO}" "${GITOPS_DIR}"
                        '''

                        dir(env.GITOPS_DIR) {
                            sh '''
                              git config user.name "jenkins-ci"
                              git config user.email "jenkins@ci.local"
                            '''
                            stash name: 'gitops-repo', includes: '**', useDefaultExcludes: false
                        }
                    }
                }
            }
        }

        /* =========================
           DOCKER LOGIN
        ========================= */
        stage('Docker Login') {
            when {
                expression { anyServiceBuildEnabled() }
            }
            steps {
                withCredentials([
                    usernamePassword(
                        credentialsId: 'dockerhub-cred',
                        usernameVariable: 'DOCKER_USER',
                        passwordVariable: 'DOCKER_PASS'
                    )
                ]) {
                    sh 'echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin'
                }
            }
        }

        stage('Prepare Trivy DB') {
            when {
                expression { anyServiceBuildEnabled() }
            }
            steps {
                sh """
                  mkdir -p ${env.TRIVY_CACHE_DIR}
                  trivy image --download-db-only --cache-dir ${env.TRIVY_CACHE_DIR}
                """
            }
        }

        /* =========================
           SERVICE PIPELINES
        ========================= */
        stage('Service Pipelines') {
            when {
                expression { anyServiceBuildEnabled() }
            }
            steps {
                script {
                    echo 'Note: GitOps updates are serialized via lock to avoid push conflicts.'
                    def tasks = [:]

                    buildServices().each { svc ->
                        def service = svc
                        tasks["Service Pipeline ${service.name}"] = {
                            catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                                stage("Test ${service.name}") {
                                    runServiceTest(service)
                                }

                                stage("Snyk Dependency Scan ${service.name}") {
                                    runSnykDependencyScan(service)
                                }

                                stage("SonarQube Analysis ${service.name}") {
                                    runSonarAnalysis(service)
                                }

                                stage("Build ${service.name}") {
                                    sh """
                                      DOCKER_BUILDKIT=1 docker build \
                                        --cache-from=${env.DOCKERHUB_USER}/${env.PROJECT}-${service.image}:latest \
                                        -t ${imageRef(service)} \
                                        -t ${env.DOCKERHUB_USER}/${env.PROJECT}-${service.image}:latest \
                                        ./${service.dir}
                                    """
                                }

                                stage("Snyk Container Scan ${service.name}") {
                                    withCredentials([
                                        string(
                                            credentialsId: 'snyk-token',
                                            variable: 'SNYK_TOKEN'
                                        )
                                    ]) {
                                        sh """
                                          set +e

                                          snyk container test "${imageRef(service)}" \
                                            --file="${service.dir}/Dockerfile" \
                                            --severity-threshold="${env.SNYK_SEVERITY}"
                                          SNYK_STATUS=\$?

                                          snyk container monitor "${imageRef(service)}" \
                                            --file="${service.dir}/Dockerfile" \
                                            --project-name="${env.PROJECT}-${service.image}" \
                                            --target-reference="${env.BRANCH_NAME ?: 'main'}" || true

                                          exit \$SNYK_STATUS
                                        """
                                    }
                                }

                                stage("Trivy Source Scan ${service.name}") {
                                    catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                                        lock(resource: 'trivy-cache') {
                                            sh """
                                              mkdir -p "${env.TRIVY_CACHE_DIR}"
                                              trivy fs \
                                                --skip-db-update \
                                                --cache-dir ${env.TRIVY_CACHE_DIR} \
                                                --severity ${env.TRIVY_SOURCE_SEVERITY} \
                                                --scanners vuln \
                                                --exit-code ${env.TRIVY_EXIT_CODE} \
                                                --ignore-unfixed \
                                                ./${service.dir}
                                            """
                                        }
                                    }
                                }

                                stage("Trivy Scan ${service.name}") {
                                    catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                                        lock(resource: 'trivy-cache') {
                                            sh """
                                              mkdir -p "${env.TRIVY_CACHE_DIR}"
                                              trivy image \
                                                --skip-db-update \
                                                --cache-dir ${env.TRIVY_CACHE_DIR} \
                                                --severity ${env.TRIVY_SEVERITY} \
                                                --exit-code ${env.TRIVY_EXIT_CODE} \
                                                --ignore-unfixed \
                                                ${imageRef(service)}
                                            """
                                        }
                                    }
                                }

                                stage("Push ${service.name}") {
                                    sh """
                                      docker push ${imageRef(service)}
                                      docker push ${env.DOCKERHUB_USER}/${env.PROJECT}-${service.image}:latest
                                    """
                                }

                                stage("GitOps Update ${service.name}") {
                                    def gitopsWorkDir = "${env.GITOPS_DIR}-${service.name}"
                                    dir(gitopsWorkDir) {
                                        deleteDir()
                                        unstash 'gitops-repo'

                                        lock(resource: 'gitops-main') {
                                            sh 'git pull --rebase origin main'
                                            updateGitOpsImageTag(service)

                                            sh """
                                              if git diff --quiet; then
                                                echo "No GitOps changes for ${service.name}"
                                                exit 0
                                              fi

                                              git add overlays/dev/kustomization.yaml
                                              git commit -m "gitops(dev): update ${service.name} image to ${IMAGE_TAG}"
                                            """

                                            retry(3) {
                                                sh 'git pull --rebase origin main'
                                                sh 'git push origin main'
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (tasks.isEmpty()) {
                        echo 'No services selected for service pipelines.'
                        return
                    }

                    parallel tasks
                }
            }
        }
    }

    post {
        always {
            script {
                cleanupBuiltImages()
            }
            sh 'docker logout || true'
        }
        success {
            echo 'CI + GitOps completed. Argo CD will sync automatically.'
        }
    }
}
