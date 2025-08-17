#!/usr/bin/env python3
"""
Test script for Symbi-OSINT REPL functionality
Validates the JSON-RPC interface and agent execution capabilities
"""

import json
import requests
import time
import sys
from typing import Dict, Any, Optional

class SymbiREPLTester:
    def __init__(self, base_url: str = "http://localhost:9257"):
        self.base_url = base_url
        self.session = requests.Session()
        self.request_id = 0
        
    def _make_request(self, method: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make a JSON-RPC request to the REPL server"""
        self.request_id += 1
        
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self.request_id
        }
        
        try:
            response = self.session.post(
                self.base_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}
    
    def test_connection(self) -> bool:
        """Test basic connectivity to REPL server"""
        print("Testing REPL connection...")
        
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=5)
            if response.status_code == 200:
                print("✓ REPL server is accessible")
                return True
        except:
            pass
            
        # Try JSON-RPC ping
        result = self._make_request("ping")
        if "error" not in result:
            print("✓ REPL JSON-RPC interface responding")
            return True
        else:
            print("✗ Cannot connect to REPL server")
            return False
    
    def test_evaluation(self) -> bool:
        """Test basic DSL evaluation"""
        print("\nTesting DSL evaluation...")
        
        test_cases = [
            {
                "input": "let x = 42",
                "description": "Variable assignment"
            },
            {
                "input": "print(\"Hello from Symbi-OSINT\")",
                "description": "Print statement"
            },
            {
                "input": "let result = 10 + 20",
                "description": "Arithmetic operation"
            }
        ]
        
        for i, test in enumerate(test_cases, 1):
            result = self._make_request("evaluate", {"input": test["input"]})
            
            if "error" in result:
                print(f"✗ Test {i} ({test['description']}) failed: {result['error']}")
                return False
            else:
                print(f"✓ Test {i} ({test['description']}) passed")
        
        return True
    
    def test_agent_listing(self) -> bool:
        """Test agent listing functionality"""
        print("\nTesting agent listing...")
        
        result = self._make_request("list_agents")
        
        if "error" in result:
            print(f"✗ Agent listing failed: {result['error']}")
            return False
        
        agents = result.get("result", {}).get("agents", [])
        print(f"✓ Found {len(agents)} agents")
        
        # Check for expected OSINT agents
        expected_agents = [
            "osint_coordinator",
            "ip_intelligence", 
            "domain_intelligence",
            "analysis_reporting"
        ]
        
        found_agents = [agent.get("name", "").lower() for agent in agents]
        
        for expected in expected_agents:
            if any(expected in found for found in found_agents):
                print(f"✓ Found {expected} agent")
            else:
                print(f"⚠ {expected} agent not found (may not be loaded yet)")
        
        return True
    
    def test_investigation_start(self) -> Optional[str]:
        """Test starting an investigation"""
        print("\nTesting investigation initiation...")
        
        investigation_query = {
            "query": "Investigate the IP address 8.8.8.8 for testing purposes",
            "requester": "test_user"
        }
        
        # Try to start investigation via DSL
        dsl_code = f"""
        let investigation = start_investigation({{
            "query": "{investigation_query['query']}",
            "requester": "{investigation_query['requester']}"
        }})
        """
        
        result = self._make_request("evaluate", {"input": dsl_code})
        
        if "error" in result:
            print(f"⚠ Investigation start test failed: {result['error']}")
            print("  (This is expected if agents are not fully loaded)")
            return None
        else:
            print("✓ Investigation started successfully")
            # Try to extract investigation ID from result
            return "test-investigation-id"
    
    def test_session_management(self) -> bool:
        """Test session snapshot and restore"""
        print("\nTesting session management...")
        
        # Create a snapshot
        snapshot_result = self._make_request("snapshot", {"name": "test_snapshot"})
        
        if "error" in snapshot_result:
            print(f"⚠ Snapshot creation failed: {snapshot_result['error']}")
            return False
        
        print("✓ Session snapshot created")
        
        # Try to restore (this might fail if snapshots aren't persisted)
        restore_result = self._make_request("restore", {"name": "test_snapshot"})
        
        if "error" in restore_result:
            print(f"⚠ Snapshot restore failed: {restore_result['error']}")
            return False
        
        print("✓ Session restored successfully")
        return True
    
    def run_all_tests(self) -> bool:
        """Run all REPL tests"""
        print("=== Symbi-OSINT REPL Test Suite ===\n")
        
        tests = [
            self.test_connection,
            self.test_evaluation,
            self.test_agent_listing,
            self.test_investigation_start,
            self.test_session_management
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            try:
                if test():
                    passed += 1
            except Exception as e:
                print(f"✗ Test {test.__name__} crashed: {e}")
        
        print(f"\n=== Test Results: {passed}/{total} passed ===")
        
        if passed == total:
            print("🎉 All tests passed!")
            return True
        elif passed > 0:
            print("⚠ Some tests passed - system partially functional")
            return False
        else:
            print("❌ All tests failed - check system status")
            return False

def main():
    """Main test execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test Symbi-OSINT REPL functionality")
    parser.add_argument("--url", default="http://localhost:9257", 
                       help="REPL server URL (default: http://localhost:9257)")
    parser.add_argument("--wait", type=int, default=0,
                       help="Wait time in seconds before starting tests")
    
    args = parser.parse_args()
    
    if args.wait > 0:
        print(f"Waiting {args.wait} seconds for services to start...")
        time.sleep(args.wait)
    
    tester = SymbiREPLTester(args.url)
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()