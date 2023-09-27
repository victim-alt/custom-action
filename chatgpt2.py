import openai
import json
import requests
import zipfile
from io import BytesIO
import os


# Sending vulnerable code snippet to ChatGPT and get remediation response. 
class ChatApp:
    def __init__(self, api_key, model="gpt-4"):
        openai.api_key = api_key
        self.messages = []
        self.model = model

    #message is the code snippet to be analyzed.
    def chat(self, message):
        self.messages.append({
            "role": "system",
            "content": "You are a security expert. Analyze the following code snippet for security vulnerabilities and propose improved code snippet for the same."
        })
        self.messages.append({"role": "user", "content": message})
        #Harsh to confirm is this is the right openai endpoint?
        response = openai.ChatCompletion.create(
            model=self.model,
            messages=self.messages,
            temperature=0.8,
            max_tokens=300,
        )

        #Appending the AI's response in meesages list as an intention of keeping the history of chats. 
        self.messages.append({"role": "assistant", "content": response["choices"][0]["message"]["content"]})
        return response["choices"][0]["message"]["content"]



def get_code_snippet_from_location(token, repo_name, file_path, start_line, end_line):

    """
        Fetch the vulnerable code snippet from the repository using GitHub API.
    """

    url = f"https://api.github.com/repos/{repo_name}/contents/{file_path}"
    
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3.raw+json"
    }

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return f"Error: {response.status_code} - {response.text}"

    content_type = response.headers.get('Content-Type')

    if "application/json" in content_type:
        json_data = response.json()
        # Assuming that the content is base64 encoded in the JSON response.
        decoded_content = base64.b64decode(json_data.get('content', ''))
        text_content = decoded_content.decode('utf-8')

    else:
        text_content = response.text

    lines = response.text.split('\n')
    return '\n'.join(lines[start_line-1:end_line])




def create_github_issue(token, repo_name, title, body):
    """
    Create a GitHub issue.

    Parameters:
    - token: Your GitHub Personal Access Token (PAT).
    - repo_name: The name of the repository in the format "owner/repo".
    - title: The title of the issue.
    - body: The content of the issue.

    Returns:
    - The created issue's URL if successful, None otherwise.
    """

    url = f"https://api.github.com/repos/{repo_name}/issues"

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    data = {
        "title": title,
        "body": body
    }

    response = requests.post(url, headers=headers, json=data)

    if response.status_code == 201:  # 201 means the issue was created successfully
        return response.json()['html_url']
    else:
        print(f"Error creating issue. Status code: {response.status_code}")
        return None



def process_vulnerabilities(sarif_file_url, api_key, github_token, repo_name):

    chat_app = ChatApp(api_key)
    with open(sarif_file_path, 'r') as f:
        sarif_content = json.load(f)

        for run in sarif_content.get('runs', []):
            for result in run.get('results', []):
                message = result.get('message', {}).get('text', '')
                locations = result.get('locations', [])
                if locations:
                    location = locations[0]
                    file_path = location['physicalLocation']['artifactLocation']['uri']
                    start_line = location['physicalLocation']['region']['startLine']
                    end_line = location['physicalLocation']['region'].get('endLine', start_line)
                    print(f"Vulnerability found in {file_path} from line {start_line} to line {end_line}")


                    # Fetch the vulnerable code snippet from the repo
                    code_snippet = get_code_snippet_from_location(github_token, repo_name, file_path, start_line, end_line)

                    chat_input = f"{message}\n\nCode Snippet:\n\n{code_snippet}"


                    # Get remediation from ChatGPT
                    print(f"Sending to ChatGPT:\n{chat_input}")
                    fix = chat_app.chat(chat_input)
                    print(f"Recommended Fix for {file_path} (lines {start_line}-{end_line}): {fix}\n\n")


                    # Create a GitHub issue for this vulnerability
                    issue_title = f"Vulnerability detected in {file_path} from line {start_line} to line {end_line}"
                    issue_body = f"{message}\n\nCode Snippet:\n\n{code_snippet}\n\nRecommended Fix:\n\n{fix}"
                    issue_url = create_github_issue(github_token, repo_name, issue_title, issue_body)
        
                    if issue_url:
                        print(f"Issue created successfully: {issue_url}")
                    else:
                         print("Error creating issue.") 



if __name__ == "__main__":
    github_token = os.environ.get('MY_GITHUB_TOKEN')
    openai_api_key = os.environ.get('OPENAI_API_KEY')
    repo_name = 'victim-alt/demo-vulnerable-nodejs'


sarif_file_path = "/home/runner/work/demo-vulnerable-nodejs/results/javascript.sarif"
process_vulnerabilities(sarif_file_path, openai_api_key, github_token, repo_name)  
