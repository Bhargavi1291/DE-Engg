import os
import re
import sys

def validate_reference_list(file_path):
    """Validate the reference list in a .txt file according to specified rules."""
    with open(file_path, 'r') as file:
        content = file.read()

    issues = []

    # Check for 'reference list' and 'type' fields
    reference_list_match = re.search(r'reference list:\s*".+?"', content, re.IGNORECASE)
    type_match = re.search(r'type:\s*(string|cidr|regex)', content, re.IGNORECASE)

    # Check for values following the 'type' field
    value_match = re.search(r'type:\s*(string|cidr|regex)\s*\n\s*(values:\s*\[.*?\])', content, re.IGNORECASE | re.DOTALL)

    if not reference_list_match:
        issues.append(f"Missing 'reference list' in {file_path}")
    
    if not type_match:
        issues.append(f"Missing or invalid 'type' in {file_path}. Must be 'string', 'cidr', or 'regex'.")
    
    if type_match and not value_match:
        issues.append(f"'type' in {file_path} must be followed by a non-empty 'values' list.")

    return issues

def main():
    base_dir = os.getenv('GITHUB_WORKSPACE', '.')
    reference_list_folder = os.path.join(base_dir, 'reference_list')
    all_issues = []

    # Check all .txt files in the reference list folder
    for root, _, files in os.walk(reference_list_folder):
        for file in files:
            if file.endswith('.txt'):
                file_path = os.path.join(root, file)
                issues = validate_reference_list(file_path)
                all_issues.extend(issues)

    if all_issues:
        for issue in all_issues:
            print(issue)
        sys.exit(1)
    else:
        print("All reference lists passed validation.")

if __name__ == "__main__":
    main()
