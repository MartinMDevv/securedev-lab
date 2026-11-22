// Pipeline DevSecOps de SecureDev Tickets (OCY1102 · Parcial 3).
//
// Etapas: Checkout → Build → SAST (Bandit) → SCA (pip-audit) → Test (pytest)
//         → Staging → DAST (OWASP ZAP autenticado) → Puerta de seguridad → Deploy
//
// Las tres etapas de seguridad corren SIEMPRE, aunque una falle (catchError), para que
// cada build deje la evidencia completa. Después, la «Puerta de seguridad» decide si se
// despliega: si alguna herramienta encontró algo, el deploy no ocurre.
//
// Todo corre dentro del contenedor de Jenkins (las herramientas vienen en su imagen),
// así Jenkins no necesita el socket de Docker del host. Ver docs del informe:
// «producción» es un gunicorn dentro del mismo contenedor (limitación del lab).

pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 45, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
        // Staging y producción usan puertos fijos: dos builds a la vez chocarían.
        disableConcurrentBuilds()
    }

    // GitHub no puede llamar a un Jenkins en localhost (no hay webhook posible),
    // así que Jenkins revisa el repo cada ~5 minutos.
    triggers {
        pollSCM('H/5 * * * *')
    }

    parameters {
        booleanParam(
            name: 'BLOQUEAR_EN_HALLAZGOS',
            defaultValue: true,
            description: 'Si está marcado, un hallazgo de seguridad falla el build y bloquea el deploy. ' +
                         'Desmarcar SOLO para desplegar la versión vulnerable y simular incidentes en Grafana.'
        )
    }

    environment {
        REPORTES      = "${WORKSPACE}/reports"
        STAGING_PORT  = '8001'
        STAGING_URL   = "http://127.0.0.1:8001"
        // «Producción» del lab: fuera del workspace para que sobreviva entre builds.
        PROD_DIR      = '/var/jenkins_home/securedev-prod'
        PROD_PORT     = '8000'
        // Sin esto, Jenkins mata los procesos en segundo plano (gunicorn) al terminar cada paso.
        JENKINS_NODE_COOKIE = 'dontKillMe'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh 'git log -1 --format="Commit %h · %an · %s"'
            }
        }

        stage('Build') {
            steps {
                sh '''
                    rm -rf .venv reports && mkdir -p reports
                    python3 -m venv .venv
                    .venv/bin/pip install --quiet --upgrade pip
                    .venv/bin/pip install --quiet -r requirements.txt -r requirements-dev.txt
                    .venv/bin/pip freeze > reports/pip-freeze.txt
                    # Validación mínima: la app tiene que poder importarse.
                    .venv/bin/python -c "from app import create_app; print('create_app OK')"
                '''
            }
        }

        stage('SAST · Bandit') {
            steps {
                catchError(buildResult: resultadoSiHallazgo(), stageResult: 'FAILURE') {
                    sh '''
                        # Reporte completo (todas las severidades) para el informe.
                        bandit -r . -x ./.venv,./tests -f html -o reports/bandit.html || true
                        bandit -r . -x ./.venv,./tests -f json -o reports/bandit.json || true
                        # Puerta: falla si hay hallazgos de severidad media o alta (-ll).
                        bandit -r . -x ./.venv,./tests -ll
                    '''
                }
            }
        }

        stage('SCA · pip-audit') {
            steps {
                catchError(buildResult: resultadoSiHallazgo(), stageResult: 'FAILURE') {
                    sh '''
                        pip-audit -r requirements.txt -r requirements-dev.txt --desc \
                                  -f json -o reports/pip-audit.json || true
                        # Puerta: cualquier dependencia con CVE conocido falla la etapa.
                        pip-audit -r requirements.txt -r requirements-dev.txt --desc \
                                  -f markdown -o reports/pip-audit.md
                    '''
                }
            }
            post {
                always {
                    sh 'cat reports/pip-audit.md 2>/dev/null || true'
                }
            }
        }

        stage('Test · pytest') {
            steps {
                sh '.venv/bin/python -m pytest -v --junitxml=reports/junit.xml'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/junit.xml'
                }
            }
        }

        stage('Staging') {
            steps {
                sh '''
                    # Jenkins corre los sh con «set -x», que imprime cada comando ya expandido:
                    # sin esto, el SECRET_KEY de staging quedaba en texto plano en la consola.
                    set +x
                    # Base de datos desechable: cada build parte con los datos de prueba.
                    rm -f staging.db staging.pid
                    DATABASE_PATH="$WORKSPACE/staging.db" \
                    SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
                    .venv/bin/gunicorn --daemon --pid staging.pid \
                        --workers 1 --threads 4 \
                        --bind 127.0.0.1:$STAGING_PORT \
                        --access-logfile reports/staging-access.log \
                        'app:create_app()'
                    ./ci/esperar-salud.sh "$STAGING_URL/health"
                '''
            }
        }

        stage('DAST · OWASP ZAP') {
            steps {
                catchError(buildResult: resultadoSiHallazgo(), stageResult: 'FAILURE') {
                    script {
                        // ci/zap.sh inicia sesión como un usuario de prueba y corre el plan
                        // security/zap.yaml con esa sesión (sin ella ZAP solo ve /login).
                        def rc = sh(script: './ci/zap.sh "$STAGING_URL" "$REPORTES"', returnStatus: true)
                        // Códigos de ZAP: 0 limpio · 1 alertas altas o error · 2 alertas medias.
                        if (rc == 2) {
                            unstable('ZAP encontró alertas de riesgo medio (ver reporte)')
                        } else if (rc != 0) {
                            error("ZAP terminó con código ${rc}: hay alertas de riesgo alto (ver reporte)")
                        }
                    }
                }
            }
            post {
                always {
                    sh 'kill "$(cat staging.pid)" 2>/dev/null || true'
                }
            }
        }

        stage('Puerta de seguridad') {
            steps {
                script {
                    if (currentBuild.currentResult == 'FAILURE') {
                        error('Hay hallazgos de seguridad: el deploy queda bloqueado.')
                    }
                    if (currentBuild.currentResult == 'UNSTABLE' && params.BLOQUEAR_EN_HALLAZGOS) {
                        echo 'Hay alertas de riesgo medio: se despliega, pero quedan registradas.'
                    }
                    if (!params.BLOQUEAR_EN_HALLAZGOS) {
                        echo '⚠️ Puerta desactivada a mano (BLOQUEAR_EN_HALLAZGOS = false).'
                    }
                }
            }
        }

        stage('Deploy') {
            // Solo la rama principal llega a producción (los PR de Dependabot se prueban, no se despliegan).
            when {
                expression { (env.GIT_BRANCH ?: '').endsWith('main') }
            }
            steps {
                sh './ci/deploy.sh'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
            publishHTML(target: [
                reportName: 'Reportes de seguridad',
                reportDir: 'reports',
                reportFiles: 'zap.html,bandit.html',
                reportTitles: 'OWASP ZAP,Bandit',
                keepAll: true,
                alwaysLinkToLastBuild: true,
                allowMissing: true
            ])
        }
    }
}

// Con la puerta activa, un hallazgo hace fallar el build; sin ella, solo lo marca inestable.
def resultadoSiHallazgo() {
    return params.BLOQUEAR_EN_HALLAZGOS ? 'FAILURE' : 'UNSTABLE'
}
