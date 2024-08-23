import os
import re
import sys

def read_reference_lists(reference_list_folder):
    """Read all reference lists from the reference_list folder and return as a dictionary."""
    reference_lists = {}
    for root, _, files in os.walk(reference_list_folder):
        for file in files:
            if file.endswith('.txt'):
                reference_name = os.path.splitext(file)[0]  # Strip the extension to get the reference list name
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    content = f.read()
                    title_match = re.search(r'title:\s*"(.*?)"', content, re.IGNORECASE)
                    type_match = re.search(r'type:\s*"(.*?)"', content, re.IGNORECASE)
                    if title_match and type_match:
                        reference_lists[reference_name] = {
                            'title': title_match.group(1),
                            'type': type_match.group(1).lower()
                        }
    return reference_lists

def validate_yara_file(file_path, reference_lists):
    """Validate the YARA file against the reference lists."""
    with open(file_path, 'r') as file:
        content = file.read()

    issues = []

    # Step 2: Find all occurrences of %referencelist-name
    references_in_yara = re.findall(r'%([a-zA-Z0-9_-]+)', content)

    for reference_name in references_in_yara:
        # Step 3: Check if reference list exists in the reference_list folder
        if reference_name not in reference_lists:
            issues.append(f"Reference list '{reference_name}' in {file_path} not found in reference_list folder.")
            continue

        reference_data = reference_lists[reference_name]

        # Step 4: Check if the title matches
        title_match = re.search(r'%{}.*?title:\s*"(.*?)"'.format(reference_name), content, re.IGNORECASE)
        if title_match and title_match.group(1) != reference_data['title']:
            issues.append(f"Title mismatch for '{reference_name}' in {file_path}. Expected title '{reference_data['title']}'.")

        # Step 5: Check the prefix in YARA file based on the type
        if reference_data['type'] == 'cidr':
            if not re.search(r'%cidr-{}'.format(reference_name), content, re.IGNORECASE):
                issues.append(f"Reference list '{reference_name}' in {file_path} should be prefixed with 'cidr-' but was not.")
        elif reference_data['type'] == 'regex':
            if not re.search(r'%regex-{}'.format(reference_name), content, re.IGNORECASE):
                issues.append(f"Reference list '{reference_name}' in {file_path} should be prefixed with 'regex-' but was not.")

    return issues

def main():
    base_dir = os.getenv('GITHUB_WORKSPACE', '.')
    rules_folder = os.path.join(base_dir, 'rules')
    reference_list_folder = os.path.join(base_dir, 'reference_list')
    all_issues = []

    # Step 1: Read all .yara or .yar files in the rules folder
    for root, _, files in os.walk(rules_folder):
        for file in files:
            if file.endswith('.yara') or file.endswith('.yar'):
                file_path = os.path.join(root, file)

                # Step 2 to Step 5: Validate YARA file against reference lists
                reference_lists = read_reference_lists(reference_list_folder)
                issues = validate_yara_file(file_path, reference_lists)
                all_issues.extend(issues)

    if all_issues:
        for issue in all_issues:
            print(issue)
        sys.exit(1)
    else:
        print("All YARA rules passed validation.")

if __name__ == "__main__":
    main()
