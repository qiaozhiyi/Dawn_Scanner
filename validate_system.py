"""
Dawn Scanner - 代码验证测试
验证各组件代码的正确性
"""

import os
import sys
import importlib.util

REPO_ROOT = os.path.abspath(os.path.dirname(__file__))


def check_go_backend():
    """检查Go后端文件"""
    print("检查Go后端文件...")
    
    backend_dir = os.path.join(REPO_ROOT, "go-backend")
    expected_files = [
        "main.go",
        "task_store.go", 
        "handlers.go",
        "report_client.go",
        "middleware.go",
        "scanner_flow.go",
        "Dockerfile"
    ]
    
    all_found = True
    for file in expected_files:
        file_path = os.path.join(backend_dir, file)
        if os.path.exists(file_path):
            print(f"  ✓ {file}")
        else:
            print(f"  ✗ {file} - NOT FOUND")
            all_found = False
    
    return all_found

def check_python_worker():
    """检查Python worker文件"""
    print("\n检查Python worker文件...")
    
    worker_dir = os.path.join(REPO_ROOT, "python-worker")
    expected_files = [
        "app.py",
        "worker.py",
        "Dockerfile"
    ]
    
    all_found = True
    for file in expected_files:
        file_path = os.path.join(worker_dir, file)
        if os.path.exists(file_path):
            print(f"  ✓ {file}")
        else:
            print(f"  ✗ {file} - NOT FOUND")
            all_found = False
    
    return all_found

def check_llm_service():
    """检查LLM服务文件"""
    print("\n检查LLM服务文件...")
    
    llm_dir = os.path.join(REPO_ROOT, "llm-service")
    expected_files = [
        "app.py",
        "requirements.txt",
        "Dockerfile"
    ]
    
    all_found = True
    for file in expected_files:
        file_path = os.path.join(llm_dir, file)
        if os.path.exists(file_path):
            print(f"  ✓ {file}")
        else:
            print(f"  ✗ {file} - NOT FOUND")
            all_found = False
    
    # 检查app.py中是否有Qwen相关的导入
    app_path = os.path.join(llm_dir, "app.py")
    with open(app_path, 'r', encoding='utf-8') as f:
        content = f.read()
        if "ChatTongyi" in content and "tongyi" in content:
            print("  ✓ Qwen API integration found in app.py")
        else:
            print("  ✗ Qwen API integration NOT FOUND in app.py")
            all_found = False
    
    return all_found

def check_docker_compose():
    """检查docker-compose文件"""
    print("\n检查Docker Compose配置...")
    
    compose_file = os.path.join(REPO_ROOT, "docker-compose.yml")
    if os.path.exists(compose_file):
        print("  ✓ docker-compose.yml")
        
        # 检查compose文件中是否有Qwen相关的配置
        with open(compose_file, 'r', encoding='utf-8') as f:
            content = f.read()
            if "DASHSCOPE_API_KEY" in content:
                print("  ✓ DASHSCOPE_API_KEY configuration found")
            else:
                print("  ⚠ DASHSCOPE_API_KEY configuration NOT FOUND")
    else:
        print("  ✗ docker-compose.yml - NOT FOUND")
        return False
    
    return True

def check_test_script():
    """检查测试脚本"""
    print("\n检查测试脚本...")
    
    test_file = os.path.join(REPO_ROOT, "test_system.py")
    if os.path.exists(test_file):
        print("  ✓ test_system.py")
        return True
    else:
        print("  ✗ test_system.py - NOT FOUND")
        return False

def validate_python_syntax():
    """验证Python文件的语法"""
    print("\n验证Python文件语法...")
    
    files_to_check = [
        os.path.join(REPO_ROOT, "llm-service", "app.py"),
        os.path.join(REPO_ROOT, "test_system.py")
    ]
    
    all_valid = True
    for file_path in files_to_check:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()
                compile(source, file_path, 'exec')
            print(f"  ✓ {os.path.basename(file_path)} - 语法正确")
        except SyntaxError as e:
            print(f"  ✗ {os.path.basename(file_path)} - 语法错误: {e}")
            all_valid = False
        except Exception as e:
            print(f"  ✗ {os.path.basename(file_path)} - 错误: {e}")
            all_valid = False
    
    return all_valid

def main():
    """主验证函数"""
    print("开始验证 Dawn Scanner 系统代码...\n")
    
    results = []
    results.append(("Go后端", check_go_backend()))
    results.append(("Python Worker", check_python_worker()))
    results.append(("LLM服务", check_llm_service()))
    results.append(("Docker Compose", check_docker_compose()))
    results.append(("测试脚本", check_test_script()))
    results.append(("Python语法", validate_python_syntax()))
    
    print("\n" + "="*50)
    print("验证结果汇总:")
    print("="*50)
    
    all_passed = True
    for name, result in results:
        status = "PASS" if result else "FAIL"
        icon = "✓" if result else "✗"
        print(f"{icon} {name:<20} {status}")
        if not result:
            all_passed = False
    
    print("="*50)
    if all_passed:
        print("✓ 所有验证通过！系统代码准备就绪。")
        print("\n要运行完整系统，您需要:")
        print("1. 安装Docker和Docker Compose")
        print("2. 运行: docker-compose up --build")
        print("3. 或运行: python3 test_system.py 来测试API")
    else:
        print("⚠ 部分验证失败。请检查上述问题。")
    
    return all_passed

if __name__ == "__main__":
    main()
