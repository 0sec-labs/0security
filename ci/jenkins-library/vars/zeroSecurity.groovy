/** Trusted shared-library step. Configure a pinned library version in Jenkins; never load it from the scanned PR. */
def call(Map config = [:]) {
  String version = config.version ?: libraryResource('0security/VERSION').trim()
  if (!(version ==~ /[0-9]+\.[0-9]+\.[0-9]+/)) error('zeroSecurity: version must be a pinned X.Y.Z release')
  if (!config.scanLabel || !config.publishLabel || config.scanLabel == config.publishLabel) error('zeroSecurity: distinct scanLabel and publishLabel are required')
  if ((!config.modelCredential && !config.modelEnv) || !config.bitbucketCredential || !config.repo) error('zeroSecurity: modelCredential (or modelEnv), bitbucketCredential and repo are required')
  // Non-secret model settings, for example [ZERO_SELECTED_PROVIDER: 'bedrock', ZERO_MODEL: '<inference profile id>', AWS_REGION: 'eu-central-1'].
  // The credential goes in modelCredential, bound to modelCredentialVariable (default OPENAI_API_KEY).
  List allowedModelEnv = ['ZERO_SELECTED_PROVIDER', 'ZERO_MODEL', 'ZERO_BEDROCK_MODEL', 'BEDROCK_BASE_URL', 'OPENAI_BASE_URL', 'AWS_REGION', 'AWS_DEFAULT_REGION', 'AWS_ROLE_ARN', 'AWS_WEB_IDENTITY_TOKEN_FILE', 'AWS_ROLE_SESSION_NAME']
  List modelEntries = []
  (config.modelEnv ?: [:]).each { name, value ->
    if (!(name in allowedModelEnv)) error("zeroSecurity: modelEnv may set only ${allowedModelEnv.join(', ')}")
    if (!(value.toString() ==~ /[A-Za-z0-9._:\/@+,=-]*/)) error("zeroSecurity: modelEnv ${name} has characters a setting should not have")
    modelEntries << "${name}=${value}".toString()
  }
  String credentialVariable = config.modelCredentialVariable ?: 'OPENAI_API_KEY'
  if (!(credentialVariable in ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GOOGLE_API_KEY', 'AWS_BEARER_TOKEN_BEDROCK'])) error('zeroSecurity: modelCredentialVariable must be OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY or AWS_BEARER_TOKEN_BEDROCK')
  String scanNode = ''
  String stashName = "zero-security-${env.BUILD_NUMBER}"
  node(config.scanLabel) {
    scanNode = env.NODE_NAME
    checkout scm
    withEnv(["VERSION=${version}", "ZEROCI_BASE_BRANCH=${config.baseBranch ?: env.CHANGE_TARGET ?: ''}", "ZEROCI_PREPASS_ONLY=${config.prepassOnly ? '1' : '0'}", "ZEROCI_TARGET=${config.target ?: '.'}", "ZEROCI_BUDGET=${config.budget ?: '3'}", "ZEROCI_FAIL_ON=${config.failOn ?: 'high'}", 'BITBUCKET_TOKEN=', 'DO_NOT_TRACK=1']) {
      String tools = pwd(tmp: true)
      dir(tools) {
        writeFile file: 'install.sh', text: libraryResource('0security/install.sh')
        writeFile file: '0-ci-scan.sh', text: libraryResource('0security/0-ci-scan.sh')
      }
      Closure runScan = {
        sh '''
          set -eu
          export INSTALL_DIR="$ZERO_TOOLS/bin" PATH="$ZERO_TOOLS/bin:$PATH"
          RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh "$ZERO_TOOLS/install.sh"
          sh "$ZERO_TOOLS/0-ci-scan.sh"
        '''
      }
      withEnv(["ZERO_TOOLS=${tools}"] + modelEntries) {
        if (config.modelCredential) {
          withCredentials([string(credentialsId: config.modelCredential, variable: credentialVariable)]) { runScan() }
        } else {
          runScan()
        }
      }
    }
    archiveArtifacts artifacts: 'scan.json,scan.exit,scan.commit', allowEmptyArchive: false
    stash name: stashName, includes: 'scan.json,scan.exit,scan.commit', useDefaultExcludes: true
  }
  // A different physical node prevents processes left by the scan from reading publisher credentials.
  node(config.publishLabel) {
    if (env.NODE_NAME == scanNode) error('zeroSecurity: publisher must run on a different Jenkins node from the scanner')
    ws(pwd(tmp: true)) {
      deleteDir()
      try {
        unstash stashName
        writeFile file: 'install.sh', text: libraryResource('0security/install.sh')
        writeFile file: '0-ci-publish.sh', text: libraryResource('0security/0-ci-publish.sh')
        withEnv(["VERSION=${version}", "ZEROCI_REPO=${config.repo}", "ZEROCI_UPLOAD_TO=${config.platform ?: 'bitbucket-dc'}", "BITBUCKET_URL=${config.bitbucketUrl ?: ''}", "ZERO_BITBUCKET_URL=${config.allowedBitbucketUrl ?: ''}", "ZERO_ENTERPRISE=${config.enterprise ? '1' : ''}", 'OPENAI_API_KEY=', 'ANTHROPIC_API_KEY=', 'GOOGLE_API_KEY=', 'AWS_BEARER_TOKEN_BEDROCK=', 'DO_NOT_TRACK=1']) {
          withCredentials([string(credentialsId: config.bitbucketCredential, variable: 'BITBUCKET_TOKEN')]) {
            sh '''
              set -eu
              for artifact in scan.json scan.exit scan.commit; do
                [ -f "$artifact" ] && [ ! -L "$artifact" ] || { echo "invalid report artifact" >&2; exit 2; }
                [ "$(wc -c < "$artifact")" -le 20971520 ] || { echo "report artifact exceeds 20 MB" >&2; exit 2; }
              done
              export INSTALL_DIR="$PWD/bin" PATH="$PWD/bin:$PATH"
              RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh install.sh
              sh 0-ci-publish.sh
            '''
          }
        }
      } finally { deleteDir() }
    }
  }
}
