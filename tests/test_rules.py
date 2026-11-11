import pytest

from guardrails.engine import evaluate_command, evaluate_tool_call
from guardrails.rules import Context

CTX = Context(cwd=".")

# (command, expected decision, expected rule)
BLOCKED = [
    # Kubernetes
    ("kubectl delete pod web-0", "deny", "kubernetes-write"),
    ("kubectl --context prod -n apps apply -f deploy.yaml", "deny", "kubernetes-write"),
    ("kubectl -n apps rollout restart deployment/web", "deny", "kubernetes-write"),
    ("kubectl scale deploy/web --replicas=0", "deny", "kubernetes-write"),
    ("helm upgrade web ./chart -n apps", "deny", "kubernetes-write"),
    ("kubectl exec -it web-0 -- sh", "ask", "kubernetes-write"),
    ("kubectl get secret db -o yaml", "deny", "kubernetes-secret-read"),
    ("kubectl get secrets/db --output=jsonpath='{.data}'", "deny", "kubernetes-secret-read"),
    ("kubectl config view --raw", "deny", "kubernetes-secret-read"),
    # hidden behind chaining, wrappers and nested shells
    ("kubectl get pods && kubectl delete pod web-0", "deny", "kubernetes-write"),
    ("kubectl get pods\nkubectl delete pod web-0", "deny", "kubernetes-write"),
    ("sudo -u ops kubectl delete ns apps", "deny", "kubernetes-write"),
    ("watch -n 5 kubectl delete pod web-0", "deny", "kubernetes-write"),
    ("KUBECONFIG=/tmp/k timeout 30 kubectl delete pod x", "deny", "kubernetes-write"),
    ("bash -lc 'kubectl delete pod web-0'", "deny", "kubernetes-write"),
    ("pwsh -Command \"kubectl delete pod web-0\"", "deny", "kubernetes-write"),
    ("echo $(kubectl delete pod web-0)", "deny", "kubernetes-write"),
    ("kubectl get pods -o name | xargs kubectl delete", "deny", "kubernetes-write"),
    ("C:\\tools\\kubectl.exe delete pod x", "deny", "kubernetes-write"),
    # credentials
    ("cat .env", "deny", "credential-read"),
    ("Get-Content C:\\app\\config\\.env.production", "deny", "credential-read"),
    ("grep -r password ~/.aws/credentials", "deny", "credential-read"),
    ("tail -n 5 deploy/id_ed25519", "deny", "credential-read"),
    ("printenv", "ask", "credential-read"),
    ("Get-ChildItem Env:", "ask", "credential-read"),
    # databases
    ("mongosh \"$URI\" --eval 'db.chats.deleteMany({})'", "deny", "database-write"),
    ("mongosh --eval 'db.x.aggregate([{$match:{}},{$out:\"y\"}])'", "deny", "database-write"),
    ("mongosh \"$URI\"", "ask", "database-write"),
    ("psql -c 'DROP TABLE users'", "deny", "database-write"),
    ("mysql -e \"update accounts set plan='x'\"", "deny", "database-write"),
    ("python -c \"import pymongo; pymongo.MongoClient().db.c.update_many({}, {'$set': {'a': 1}})\"", "deny",
     "database-write"),
    ("python - <<'EOF'\nimport pymongo\nc = pymongo.MongoClient()\nc.db.users.delete_one({'_id': 1})\nEOF",
     "deny", "database-write"),
    # cloud
    ("aws s3 cp backup.tar.gz s3://bucket/backups/", "deny", "cloud-write"),
    ("aws --profile prod s3 sync ./out s3://bucket/site --delete", "deny", "cloud-write"),
    ("aws s3 rm s3://bucket/key", "deny", "cloud-write"),
    ("aws ec2 terminate-instances --instance-ids i-123", "ask", "cloud-write"),
    ("python3 -c 'import boto3; boto3.client(\"s3\").delete_object(Bucket=\"b\", Key=\"k\")'", "deny", "cloud-write"),
    ("terraform apply -auto-approve", "deny", "terraform-write"),
    ("terraform state rm aws_instance.web", "deny", "terraform-write"),
    # git
    ("git push --force origin feature", "deny", "git-danger"),
    ("git push origin +feature", "deny", "git-danger"),
    ("git push origin main", "deny", "git-danger"),
    ("git push origin HEAD:refs/heads/master", "deny", "git-danger"),
    ("git reset --hard HEAD~3", "ask", "git-danger"),
    # processes
    ("pkill -f gunicorn", "deny", "kill-by-name"),
    ("taskkill /IM python.exe /F", "deny", "kill-by-name"),
    ("Stop-Process -Name node", "deny", "kill-by-name"),
    # cannot be analyzed
    ("echo 'unbalanced", "ask", "unparsable"),
]

ALLOWED = [
    "kubectl get pods -A",
    "kubectl -n apps logs deploy/web --since=10m",
    "kubectl get pods -l app=delete",           # "delete" as a label value is not a verb
    "kubectl describe secret db",                # describe does not print values
    "kubectl get secrets",                       # names only
    "kubectl -n observability port-forward svc/loki 31000:3100",
    "kubectl rollout status deployment/web",
    "helm list -A",
    "cat README.md",
    "cat .env.example",
    "ls -la ~/.ssh/id_ed25519.pub",
    "mongosh \"$URI\" --eval 'db.chats.find({}).limit(5)'",
    "psql -c 'select count(*) from users'",
    "aws s3 cp s3://bucket/report.csv ./report.csv",
    "aws s3 ls s3://bucket/",
    "aws ec2 describe-instances",
    "terraform plan",
    "git push origin feature/x",
    "git status && git diff",
    "kill 12345",
    "Stop-Process -Id 12345",
    "python -m pytest -q",
]


@pytest.mark.parametrize("command,decision,rule", BLOCKED)
def test_blocked(command, decision, rule):
    verdict = evaluate_command(command, CTX)
    assert verdict is not None, f"expected {decision} for: {command}"
    assert (verdict.decision, verdict.rule) == (decision, rule)


@pytest.mark.parametrize("command", ALLOWED)
def test_allowed(command):
    verdict = evaluate_command(command, CTX)
    assert verdict is None, f"unexpected {verdict} for: {command}"


def test_deny_wins_over_ask():
    verdict = evaluate_command("printenv; kubectl delete pod x", CTX)
    assert verdict.decision == "deny"


@pytest.mark.parametrize("tool,payload,decision", [
    ("Read", {"file_path": "/srv/app/.env"}, "deny"),
    ("Read", {"file_path": "/srv/app/settings.py"}, None),
    ("Grep", {"pattern": "token", "path": "/home/me/.aws/credentials"}, "deny"),
    ("Bash", {"command": "kubectl delete pod x"}, "deny"),
    ("WebFetch", {"url": "https://example.com"}, None),
])
def test_tool_calls(tool, payload, decision):
    verdict = evaluate_tool_call(tool, payload, CTX)
    assert (verdict.decision if verdict else None) == decision


def test_extra_secret_patterns():
    ctx = Context(cwd=".", extra_secret_patterns=("*.ini",))
    assert evaluate_command("cat configs/app.ini", ctx).rule == "credential-read"
    assert evaluate_command("cat configs/app.ini", CTX) is None
