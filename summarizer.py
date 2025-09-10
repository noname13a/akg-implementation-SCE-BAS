import openai, textwrap

# Prompt base para extraer el "estado" de cada táctica a partir de un bloque de texto CTI.
# Aquí defino las reglas para que el modelo resuma la información relevante en cinco categorías.

STATE_PROMPT = textwrap.dedent("""
You are an assistant who can analyze cyber threat intelligence and extract information that is needed, here are the rules for you to follow:
    
[Rules]
Rule 1: The extraction content includes five categories: ‘‘permission state, file collection, information collection, tool set, stage summary’’.
Rule 2: The meanings of the five categories are as follows:
1. permission state: The permissions obtained by the attackers involved in the article, default is user;
2. file collection: This article describes the files that attackers obtain from victims; For example,.txt,.doc,.jpg and other file formats.
3. information collection: This article describes the information that attackers obtain from victims; Such as passwords, personal information, account information, and
other valuable information;
4. tool set: The tool in the article used by the attacker to achieve the purpose;
5. stage summary: Summarize the content of the text in one sentence, no more than 20 words.
Rule 3: The output format is as follows: permission state:(); file collection:(); information collection:(); tool set:(); stage summary:();

[Example]
Here are examples of Information extraction, and the paragraphs are given as follows:
    
Example 1:
Cisco Talos has observed a new campaign targeting Turkish private organizations and governmental institutions. This campaign utilizes malicious PDFs, XLS files, and
Windows executables to deploy malicious PowerShell-based downloaders acting as initial footholds into the target’s enterprise. The PDF files typically show an error
message and ask the user to click on a link to resolve the issue and display the correct format/extension of the document. Once the victim clicks on the download
button, the endpoint receives a second stage, which can be either a malicious XLS file or a Windows executable that proceeds with the infection as described earlier.
The summary is:
permission set:(user);
file collection:(PDFs, XLS files, Windows executables);
information collection:();
tool set:(PowerShell-based downloaders);
stage summary:(Campaign targeting Turkish entities with malicious documents and downloaders.);
Example 2:
The malware ‘Backdoor.Agent.Hza’, dropped by the trojaned update file, executed on the infected SK Communications computers, establishing a backdoor for the
attackers. The malware communicated with a command and control server located at the South Korean IP address 116.127.121.41 on TCP port 8080. The attackers also
installed additional malware named ‘nateon.exe’ on at least one of the infected computers, which was used to access the user databases.
permission set:(user);
file collection:(user databases);
infomation collection:();
tool set:(Backdoor.Agent.Hza, nateon.exe);
stage summary:(Malware created backdoor access to SK Communications computers.);

[Paragraphs]
Please summarize the paragraphs:
""").strip()

# Esta función toma el texto de una táctica y pide al modelo que lo resuma en las cinco categorías definidas.
# El resultado es un string con el resumen estructurado, siguiendo el formato del prompt.
def summarize_stage(tactic_paragraph):
    # Inserto el texto en el prompt en el sitio correcto
    #[paragraphs]
    #[Output]
    #The summary is: [Stage state summary of cyber threat intelligence]
    #prompt = STATE_PROMPT.replace("[paragraphs]", tactic_paragraph.strip())
    prompt = STATE_PROMPT  + tactic_paragraph
    messages = [
        {"role": "system",
         "content": "You are a CTI stage summarizer."},
        {"role": "user",
         "content": prompt}
    ]
    resp = openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        temperature=0.2
    )
    return resp.choices[0].message.content.strip()
