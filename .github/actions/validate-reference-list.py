import os
import re
import sys

def validate_reference_list(file_path):
    """Validate the reference list in a .txt file according to specified rules."""
    with open(file_path, 'r') as file:
        content = file.read()

    issues = []

    # Check for 'type' field with valid values
    type_match = re.search(r'type:\s*"(string|cidr|regex)"', content, re.IGNORECASE)
    if not type_match:
        issues.append(f"Missing or invalid 'type' in {file_path}. Must be 'string', 'cidr', or 'regex'.")

    # Check for 'Title' field
    title_match = re.search(r'title:\s*".+?"', content, re.IGNORECASE)
    if not title_match:
        issues.append(f"Missing 'Title' in {file_path}")

    # Check for 'Description' field
    description_match = re.search(r'description:\s*".+?"', content, re.IGNORECASE)
    if not description_match:
        issues.append(f"Missing 'Description' in {file_path}")

    # Check for 'row' field with non-empty values, either on the same line or subsequent lines
    row_match = re.search(r'row:\s*([^\s].*|(\n\s+[^\s].*))', content, re.IGNORECASE | re.MULTILINE)
    if not row_match:
        issues.append(f"Missing or empty 'row' in {file_path}")

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
