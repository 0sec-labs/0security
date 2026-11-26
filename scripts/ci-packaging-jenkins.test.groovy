// Execute the real shared-library Groovy control flow with a minimal Jenkins step harness.
// This is not a Jenkins controller or a live-agent qualification.
// java -cp /path/to/groovy.jar groovy.ui.GroovyMain scripts/ci-packaging-jenkins.test.groovy REPO_ROOT
assert args.length == 1
File root = new File(args[0])
String source = new File(root, 'ci/jenkins-library/vars/zeroSecurity.groovy').text

def runLibrary = { Map config, boolean samePhysicalNode = false ->
  Map environment = [BUILD_NUMBER: '7', NODE_NAME: '', CHANGE_TARGET: 'main']
  def script = new GroovyShell(new Binding([env: environment, scm: 'trusted-checkout'])).parse(source)
  List events = []
  script.metaClass.error = { String message -> throw new IllegalStateException(message) }
  script.metaClass.libraryResource = { String name ->
    assert name.startsWith('0security/')
    def filename = name.substring('0security/'.length())
    filename == 'VERSION' ? '0.45.0\n' : new File(root, filename == 'install.sh' ? filename : "ci/scripts/${filename}").text
  }
  script.metaClass.node = { String label, Closure body ->
    def previous = environment.NODE_NAME
    environment.NODE_NAME = samePhysicalNode ? 'shared-node' : label
    events << "node:${environment.NODE_NAME}"
    try { body() } finally { environment.NODE_NAME = previous }
  }
  script.metaClass.checkout = { value -> assert environment.NODE_NAME == 'scan' || samePhysicalNode; events << 'checkout' }
  script.metaClass.pwd = { Map options = [:] -> "/tmp/zero-security-${environment.NODE_NAME}" }
  script.metaClass.dir = { String path, Closure body -> body() }
  script.metaClass.ws = { String path, Closure body -> body() }
  script.metaClass.writeFile = { Map options -> assert options.text; events << "write:${options.file}" }
  script.metaClass.deleteDir = { -> events << 'delete' }
  script.metaClass.string = { Map options -> options }
  script.metaClass.withEnv = { List<String> entries, Closure body ->
    Map before = new LinkedHashMap(environment)
    entries.each { item -> int split = item.indexOf('='); environment[item.substring(0, split)] = item.substring(split + 1) }
    try { body() } finally { environment.clear(); environment.putAll(before) }
  }
  script.metaClass.withCredentials = { List credentials, Closure body ->
    Map before = new LinkedHashMap(environment)
    credentials.each { item -> environment[item.variable] = "credential:${item.credentialsId}" }
    try { body() } finally { environment.clear(); environment.putAll(before) }
  }
  script.metaClass.sh = { String shell ->
    assert shell.contains('RELEASE_BASE_URL=') && shell.contains('releases/download/v${VERSION}')
    if (shell.contains('0-ci-scan.sh')) {
      assert environment.NODE_NAME == 'scan' || samePhysicalNode
      assert environment.OPENAI_API_KEY == 'credential:model'
      assert !environment.BITBUCKET_TOKEN
      events << 'scan'
    } else {
      assert environment.NODE_NAME == 'publish'
      assert !environment.OPENAI_API_KEY
      assert environment.BITBUCKET_TOKEN == 'credential:bitbucket'
      events << 'publish'
    }
  }
  script.metaClass.archiveArtifacts = { Map options -> assert options.artifacts == 'scan.json,scan.exit,scan.commit'; events << 'archive' }
  script.metaClass.stash = { Map options -> assert options.includes == 'scan.json,scan.exit,scan.commit'; events << 'stash' }
  script.metaClass.unstash = { String name -> assert events.contains('stash'); assert environment.NODE_NAME == 'publish' || samePhysicalNode; events << 'unstash' }
  script.call(config)
  assert events.indexOf('scan') < events.indexOf('publish')
  assert events.count('checkout') == 1
  assert events.count('delete') == 2
  events
}
Map valid = [scanLabel: 'scan', publishLabel: 'publish', modelCredential: 'model', bitbucketCredential: 'bitbucket', repo: 'P/r', bitbucketUrl: 'https://code.example']
assert runLibrary(valid).contains('publish')
for (Map invalid : [valid + [version: 'latest'], valid + [scanLabel: 'publish'], valid + [modelCredential: '']]) {
  try { runLibrary(invalid); assert false : 'invalid configuration should fail' } catch (IllegalStateException expected) { }
}
try { runLibrary(valid, true); assert false : 'same physical node should fail' } catch (IllegalStateException expected) { assert expected.message.contains('different Jenkins node') }
println 'Jenkins library control-flow tests passed: credential scopes, one checkout, artifact transfer, distinct nodes, cleanup and pinned-version validation.'
