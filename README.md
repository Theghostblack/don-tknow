# don-tknow
i don't know
Project For SIH Download the tool and start using


Usage Instructions (Step-by-Step for Judges & Hackathon Submission)

 1. **Install the prerequisites**
- Python 3.x
- Subfinder
- HTTPX
- Nuclei (optional)
- FFUF
- waybackurls
- OpenAI Python client
- python-docx
- Ensure the required wordlists exist at the specified paths.

### 2. **Set your OpenRouter API key**


### 3. **Run the tool**
**git clone**
```shell
git clone 
```
-it install all package's

**install package**
```shell
pip install requirement.txt
```
**run**
```shell
python3 main.py
```

### 4. **Review the Output**
- All results and the final AI-generated security report are stored in a folder named after the target domain.
- The main report will be saved as a DOCX file at:  
  `./example.com/report/example.com_report.docx`

### 5. **What does it do?**
- Finds subdomains of the target.
- Checks which subdomains are alive.
- Optionally runs vulnerability scans with Nuclei.
- Fuzzes for virtual hosts and directories.
- Scrapes historical URLs via Wayback Machine.
- Fuzzes for XSS and SQLi vulnerabilities.
- Aggregates all findings.
- Generates a professional report using AI.
