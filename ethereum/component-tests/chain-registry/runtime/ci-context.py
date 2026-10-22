import json, os, pathlib, subprocess, sys
event = json.loads(pathlib.Path(os.environ['GITHUB_EVENT_PATH']).read_text())
git = lambda *args: subprocess.check_output(['git', *args], text=True).strip()
selected = ['GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT',
            'GITHUB_EVENT_NAME', 'GITHUB_SHA', 'GITHUB_REF', 'GITHUB_JOB',
            'GITHUB_WORKFLOW_REF', 'GITHUB_WORKFLOW_SHA', 'RUNNER_OS', 'RUNNER_ARCH']
value = {'scope': 'Unsigned CI checkout/job observation; not a runtime or operating verdict',
         'environment': {key: os.environ[key] for key in selected},
         'group': 'ordinary-constructor',
         'checkout': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
         'parents': [line.split()[1] for line in
                     git('cat-file', '-p', 'HEAD').split('\n\n', 1)[0].splitlines()
                     if line.startswith('parent ')],
         'node': subprocess.check_output(['node', '--version'], text=True).strip(),
         'python': sys.version}
if os.environ['GITHUB_EVENT_NAME'] == 'pull_request':
    pull = event['pull_request']
    value['pull_request'] = {'number': event['number'],
                             'base': pull['base']['sha'], 'head': pull['head']['sha']}
with pathlib.Path(__file__).resolve().parent.joinpath('evidence/ci-context.json').open('x') as stream:
    json.dump(value, stream, indent=2)
    stream.write('\n')
print(json.dumps(value))
