import openai, textwrap

# Prompt para identificar la técnica MITRE ATT&CK más adecuada para cada bloque de texto.
# Aquí defino las reglas y ejemplos que quiero que siga el modelo para etiquetar correctamente.

TECH_ID_PROMPT = textwrap.dedent("""
You are an assistant and your task is to select the technique-level tag that
best matches the meaning of the textafter analyzing the text in a cyber threat intelligence
report based on how well the text content matches the candidate tags. Your task flow
is based on the following rules:
    
[Rules]
Rule 1: Please label the sentences in the given text with the technique-level candidate tags.
If some sentences in the text may not belong to any of the candidate tags,
please skip them and do not add the sentence number of them to your response.
The candidate tags are as follows:‘‘[Techniques]’’
Rule 2: The meaning of the candidate tags is as follows:
1. [Technique]: [Description of Technique]
2. ......

[Example]
This is an example of content types label, and the texts are given as follows:
0: device; load; malware; When the device is inserted into another system, it opens autorun.inf and loads the malware.
1: Sandworm Team; use; valid accounts; During the 2015 Ukraine Electric Power Attack, Sandworm Team used valid accounts on the corporate network to escalate
privileges, move laterally, and establish persistence within the corporate network.
2: APT28; access; DCCC network; Once APT28 gained access to the DCCC network, the group then proceeded to use that access to compromise the DNC network.
3: Andariel; use; watering hole attacks; Andariel has used watering hole attacks, often with zero-day exploits, to gain initial access to victims within a specific IP range.
4: Disco; redirect; targeted hosts; Disco has achieved initial access and execution through content injection into DNS, HTTP, and SMB replies to targeted hosts that
redirect them to download malicious files.
5: APT28; conduct; SQL injection attacks; APT28 has used a variety of public exploits, including CVE 2020-0688 and CVE 2020-17144, to gain execution on vulnerable
Microsoft Exchange; they have also conducted SQL injection attacks against external websites.
6: Sandworm Team; use; Dropbear SSH client; During the 2015 Ukraine Electric Power Attack, Sandworm Team installed a modified Dropbear SSH client as the backdoor
to target systems.
7: DarkVishnya; connect-to; company’s local network; DarkVishnya used Bash Bunny, Raspberry Pi, netbooks or inexpensive laptops to connect to the company’s local
network.
8: Agent.btz; create; autorun.inf file; Agent.btz drops itself onto removable media devices and creates an autorun.inf file with an instruction to run that file.
9: Axiom; use; spear phishing; Axiom has used spear phishing to initially compromise victims.
......
Labeled articles are:
T1659-Content Injection:(4)
T1189-Drive-by Compromise:(3)
T1190-Exploit Public-Facing Application:(5)
T1133-External Remote Services:(6)
T1200-Hardware Additions:(7)
T1566-Phishing:(9)
T1091-Replication Through Removable Media:(0,8)
T1195-Supply Chain Compromise:()
T1199-Trusted Relationship:(2)
T1078-Valid Accounts:(1)
......
[Text]
Please label the texts below with the given techniques:
""").strip()

#[paragraphs]
#[Output]
#The summary is: [Stage state summary of cyber threat intelligence]

# Esta función toma un bloque de tripletas y pide al modelo que asigne la tecnica MITRE más adecuada.
# El resultado es un string con las etiquetas asignadas, siguiendo el formato del prompt.
def tag_techniques(triplets_block):
    # Preparo los mensajes para el modelo: primero el rol del sistema, luego el prompt con el bloque de tripletas.
    messages = [
        {"role": "system",
         "content": "You are a MITRE ATT&CK technique matcher."},
        {"role": "user",
         "content": TECH_ID_PROMPT + triplets_block}
    ]
    # Llamo al modelo de OpenAI con los parametros indicados.
    resp = openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        temperature=0.0
    )
    # Devuelvo solo el contenido de la respuesta, limpio de espacios.
    return resp.choices[0].message.content.strip()
