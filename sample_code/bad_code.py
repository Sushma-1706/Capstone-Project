import os
import subprocess

# Intentionally poor code for static analysis testing

def process_data(data):
    """A very complex and poorly structured function for Radon/Pylint testing."""
    result = []
    
    # Missing variable usage (Pylint warning)
    unused_var = "I am not used"
    
    # Complex nesting structure (Radon cyclomatic complexity warning)
    if data:
        for item in data:
            if isinstance(item, dict):
                if 'status' in item:
                    if item['status'] == 'active':
                        if 'value' in item:
                            if item['value'] > 10:
                                for key in item:
                                    if key.startswith('x_'):
                                        result.append(item[key])
                            else:
                                if item.get('retry', False):
                                    result.append('retrying')
                                else:
                                    result.append('skipped_value')
                    elif item['status'] == 'pending':
                        if 'priority' in item:
                            if item['priority'] == 'high':
                                result.append('urgent')
                            elif item['priority'] == 'medium':
                                result.append('normal')
                            else:
                                result.append('low')
                        else:
                            result.append('unknown')
                    else:
                        result.append('ignored')
                else:
                    pass
            elif isinstance(item, list):
                for subitem in item:
                    if subitem:
                        result.append(subitem)
    
    return result

def insecure_system_call():
    """An insecure function for Bandit security testing."""
    # Hardcoded sensitive data (Bandit warning)
    api_key = "abcdef1234567890"  # This is a bad idea
    password = "super_secret_password"
    
    # Unsafe subprocess usage without escaping (Bandit warning)
    user_input = "some_user_input"
    subprocess.run("ping " + user_input, shell=True)
    
    # Unsafe direct file operation (Bandit warning)
    filename = "/etc/shadow"
    with open(filename, 'r') as f:
        print(f.read())
        
    return api_key

# Poor naming convention (Pylint convention)
BADNameVariable = 42

class poorlyNamedClass:
    # No __init__ and poor naming
    def DoSomething(self):
        # Broad exception (Pylint warning)
        try:
            x = 1 / 0
        except Exception:
            pass

def parse_error():
    # This will parse correctly as AST syntax but trigger other analysis tools
    pass
