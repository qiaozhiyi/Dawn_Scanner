"""
Dawn Scanner - 测试脚本
用于验证系统的各个组件是否正常工作
"""

import requests
import json
import time
import uuid

# 配置
BASE_URL = "http://localhost:8080"
AUTH_TOKEN = "dawn_scanner_dev_token"  # 默认开发环境token
HEADERS = {
    "Authorization": f"Bearer {AUTH_TOKEN}",
    "Content-Type": "application/json"
}

def test_health():
    """测试健康检查端点"""
    print("Testing health endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/health")
        if response.status_code == 200:
            print(f"✓ Health check passed: {response.json()}")
            return True
        else:
            print(f"✗ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ Health check error: {e}")
        return False

def test_submit_scan():
    """测试提交扫描任务"""
    print("\nTesting submit scan task...")
    try:
        # 提交一个测试URL
        test_url = "https://httpbin.org/get"  # 一个公开的测试网站
        payload = {
            "url": test_url
        }
        
        response = requests.post(f"{BASE_URL}/api/tasks", 
                                headers=HEADERS, 
                                json=payload)
        
        if response.status_code == 201:
            result = response.json()
            print(f"✓ Scan task submitted successfully: {result}")
            return result.get('task_id')
        else:
            print(f"✗ Failed to submit scan task: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"✗ Submit scan error: {e}")
        return None

def test_get_task(task_id):
    """测试获取任务状态"""
    print(f"\nTesting get task status for ID: {task_id}")
    try:
        response = requests.get(f"{BASE_URL}/api/tasks/{task_id}", headers=HEADERS)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✓ Got task status: {result['status']}")
            return result
        else:
            print(f"✗ Failed to get task: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"✗ Get task error: {e}")
        return None

def test_list_tasks():
    """测试列出所有任务"""
    print("\nTesting list tasks...")
    try:
        response = requests.get(f"{BASE_URL}/api/tasks", headers=HEADERS)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✓ Listed tasks: Found {len(result.get('tasks', []))} tasks")
            return result
        else:
            print(f"✗ Failed to list tasks: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"✗ List tasks error: {e}")
        return None

def wait_for_task_completion(task_id, max_wait=60):
    """等待任务完成"""
    print(f"\nWaiting for task {task_id} to complete...")
    start_time = time.time()
    
    while time.time() - start_time < max_wait:
        task_info = test_get_task(task_id)
        if task_info and task_info.get('status') in ['completed', 'failed']:
            print(f"Task {task_id} finished with status: {task_info['status']}")
            return task_info
        time.sleep(5)  # 等待5秒再检查
    
    print(f"Task {task_id} did not complete within {max_wait} seconds")
    return None

def main():
    """主测试函数"""
    print("Starting Dawn Scanner System Test...\n")
    
    # 1. 测试健康检查
    health_ok = test_health()
    if not health_ok:
        print("System health check failed. Exiting.")
        return
    
    # 2. 测试提交扫描任务
    task_id = test_submit_scan()
    if not task_id:
        print("Failed to submit scan task. Exiting.")
        return
    
    # 3. 测试列出任务
    test_list_tasks()
    
    # 4. 等待任务完成并检查最终状态
    final_status = wait_for_task_completion(task_id)
    
    if final_status:
        print(f"\nFinal task status: {final_status['status']}")
        if final_status['status'] == 'completed':
            print("✓ Scan completed successfully!")
            if final_status.get('result'):
                vulns = final_status['result'].get('vulnerabilities', [])
                print(f"✓ Found {len(vulns)} vulnerabilities in the scan")
        else:
            print(f"⚠ Task finished with status: {final_status['status']}")
    else:
        print("⚠ Could not get final task status")
    
    print("\nTest completed!")

if __name__ == "__main__":
    main()