"""
CCK LangGraph Integration Example.

Demonstrates using CCK as a zero-bypass pre-tool gate in LangGraph workflows.
Ensures tools (like courier dispatch, billing charges, or cloud mutations)
are never executed if underlying facts have drifted or expired.
"""

from typing import Any, Dict
import requests

CCK_BASE_URL = "http://localhost:3000"

def cck_verify_action_gate(
    capability: str,
    target: str,
    command: str,
    entity_id: str,
    severity: str = "MUTATION"
) -> Dict[str, Any]:
    """
    Evaluates an intended action against CCK before calling the tool.
    Returns:
        Dict with 'decision' ('ALLOW', 'BLOCK', 'REQUIRE_APPROVAL', 'REVALIDATE')
        and full verification receipt.
    """
    payload = {
        "capability": capability,
        "target": target,
        "command": command,
        "entity_id": entity_id,
        "severity": severity,
        "agent": "langgraph-agent-fulfillment"
    }
    
    response = requests.post(f"{CCK_BASE_URL}/api/v1/actions/evaluate", json=payload, timeout=5)
    response.raise_for_status()
    return response.json()


# LangGraph tool node execution wrapper
def protected_shipping_tool(order_id: str, courier: str) -> str:
    print(f"\n[LangGraph Tool] Intending to dispatch shipment for order {order_id} via {courier}...")
    
    # Pre-execution zero-bypass check
    verdict = cck_verify_action_gate(
        capability="logistics.ship",
        target=f"courier.{courier}",
        command=f'dispatch_order("{order_id}")',
        entity_id=f"order:{order_id}",
    )
    
    decision = verdict.get("decision")
    print(f"[CCK Gate Decision]: {decision} (Risk Score: {verdict.get('risk_score')})")
    
    if decision == "ALLOW":
        # Safe to execute external mutation
        return f"SUCCESS: Order {order_id} dispatched via {courier}. Decision Receipt: {verdict.get('receipt_id')}"
    elif decision == "BLOCK":
        # Blocked: Precondition drifted or policy violated
        reason = verdict.get("reason", "Precondition invalid")
        print(f"[MUTATION BLOCKED]: {reason}")
        return f"BLOCKED: Action aborted. {reason}"
    else:
        return f"HOLD: Decision status {decision}. Action requires revalidation or approval."


if __name__ == "__main__":
    # Test dispatch when order:1099 is valid
    print("--- Test 1: Active Paid Order ---")
    result = protected_shipping_tool("1099", "fedex")
    print(result)
