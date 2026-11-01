"""
CCK OpenAI Agents SDK / Function Calling Guard.

Demonstrates wrapping OpenAI tool function calls with CCK Action Gate
to protect against executing actions on stale or hallucinated assumptions.
"""

import json
import urllib.request

CCK_HOST = "http://localhost:3000"

def evaluate_tool_call(tool_name: str, arguments: dict, entity_id: str) -> dict:
    url = f"{CCK_HOST}/api/v1/actions/evaluate"
    payload = json.dumps({
        "capability": f"tool.{tool_name}",
        "target": "external.api",
        "command": json.dumps(arguments),
        "entity_id": entity_id,
        "severity": "MUTATION",
        "agent": "openai-assistant"
    }).encode("utf-8")
    
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def execute_openai_tool_safely(tool_name: str, arguments: dict, entity_id: str):
    print(f"[OpenAI Tool Call Requested]: {tool_name} with {arguments}")
    
    verdict = evaluate_tool_call(tool_name, arguments, entity_id)
    if verdict.get("decision") != "ALLOW":
        print(f"[CCK BLOCKED ACTION]: {verdict.get('reason')}")
        return {
            "status": "error",
            "code": "CCK_ACTION_BLOCKED",
            "message": verdict.get("reason"),
            "receipt_id": verdict.get("receipt_id")
        }
    
    # Safe to execute real mutation
    print(f"[CCK APPROVED]: Executing mutation. Receipt: {verdict.get('receipt_id')}")
    return {"status": "success", "data": "Executed safely"}


if __name__ == "__main__":
    res = execute_openai_tool_safely("refund_order", {"order_id": "1099", "amount": 99.0}, "order:1099")
    print("Result:", res)
