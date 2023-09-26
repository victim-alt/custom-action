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



# Get the file path of sharif filw where codeql analysis is stored.

# Need to debug this Github API to list artifacts, how does it gives the codeql sharif file to be downloaded in the response. 
def get_sarif_filepath(token):


    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    url = "https://api.github.com/repos/victim-alt/demo-vulnerable-nodejs/actions/artifacts"  
    response = requests.get(url, headers=headers)

    # Check for successful response
    if response.status_code != 200:
        print(f"Error fetching artifacts. Status code: {response.status_code}")
        return None

    artifacts = response.json().get('artifacts', [])
    
    # Artifact is explicitly set to codeql-sarif in upload-artifact step.
    for artifact in artifacts:
        if artifact['name'] == 'codeql-sarif':
            return artifact['archive_download_url']

    print(f"Artifact 'codeql-sarif' not found among artifacts.")
    return None



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
    
    headers = {
    "Authorization": f"token {github_token}",
    "Accept": "application/vnd.github.v3+json"
    }

    # Artifacts are stored in the form of zip.
    response = requests.get(sarif_file_url, headers=headers)
   
    # print(response.headers.get('Content-Type'))
    if response.status_code != 200:
        print(f"Unexpected status code: {response.status_code}")
        print(response.text[:500])  # print first 500 characters of the response   
        return


    with zipfile.ZipFile(BytesIO(response.content)) as z:
        # List of all SARIF files in the ZIP
        sarif_files = [name for name in z.namelist() if name.endswith('.sarif')]


        # Process each SARIF file
        for sarif_file in sarif_files:
            with z.open(sarif_file) as f:
                sarif_content = json.load(f)

                # Iterate through the vulnerabilities   
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




################################################## Loading Configs. ################################################


if __name__ == "__main__":
    github_token = os.environ.get('MY_GITHUB_TOKEN')
    openai_api_key = os.environ.get('OPENAI_API_KEY')
    repo_name = 'victim-alt/demo-vulnerable-nodejs'  



################################################# Config Loaded. ###################################################
                                      
sarif_file_path = get_sarif_filepath(github_token)
print(sarif_file_path)
process_vulnerabilities(sarif_file_path, openai_api_key, github_token, repo_name)
