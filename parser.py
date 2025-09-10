import openai, textwrap

# Prompt base para extraer tripletas de entidades y relaciones de un texto CTI.
# Aquí defino las reglas que quiero que siga el modelo para estructurar la información.

TRIPLET_PROMPT = textwrap.dedent("""
You are an assistant to perform structured entity extraction and relation extraction from articles, especially in the domain of Cyber Threat Intelligence(CTI) report,
according to the following rules:
[Rules]
Rule 1: Extract each entity group in the format: ‘‘entity 1(entity type); relation; entity 2(entity type); article_id.’’ article_id is the id of the article which the triplets are
extracted from.
Rule 2: Extract entities only from the following candidate entity types: ‘‘[Entities]’’
Rule 3: Extract relations from the following candidate relation types, and you can add some other relations if you think that is reasonable: ‘‘[Relations]’’
Rule 4: When extracting triplets, pronouns such as ‘it’, ‘they’, ‘he’, ‘she’, ‘we’, etc., should be converted to their synonymous names in the original text and then extracted.
Rule 5: The description of the relations for all the triplets should use the active voice in the present simple tense and should not use the passive voice or singular third
person.
[Example]
Please Extract the security-related triplets in the articles below:
article 0:
APT-X used MURKYSHELL at a compromised victim organization to port scan IP addresses and conduct network enumeration. APT-X frequently uses native Windows
commands, such as net.exe, to conduct internal reconnaissance of a victim’s environment. Web shells are heavily relied on for nearly all stages of the attack lifecycle.
Internal web servers are often not configured with the same security controls as public-facing counterparts, making them more vulnerable to exploitation by APT-X and
similarly sophisticated groups.
article 1:
APT-X used MURKYSHELL at a compromised victim organization to port scan IP addresses and conduct network enumeration. APT-X frequently uses native Windows
commands, such as net.exe, to conduct internal reconnaissance of a victim’s environment.
article 2: The StellarParticle campaign, associated with COZY BEAR, utilized various initial access techniques. They gained access to the victim’s network by logging into
a public-facing system via Secure Shell (SSH) using a local account acquired during previous credential theft activities. They also used port forwarding capabilities to
establish a Remote Desktop Protocol (RDP) session to internal servers using different domain accounts. Additionally, the threat actor used VPNs to gain access to systems
and persist in the environment. They exported saved passwords from users’ Chrome browser installations.
Extracted results:
APT-X(threat-actor) ; Use ; MURKYSHELL(Malware); 0
APT-X(threat-actor) ; Use ; net.exe(Tool); 0
APT-X(threat-actor) ; Exploit ; internal web
servers(Infrastructure); 0
Web shells(Tool) ; Host ; internal web servers(Infrastructure); 0
APT-X(threat-actor) ; Use ; MURKYSHELL(Malware); 1
APT-X(threat-actor) ; Use ; net.exe(Tool); 1
StellarParticle(campaign) ; Associate-with ; COZY BEAR(threat-actor); 2
StellarParticle(campaign) ; Use ; Secure Shell(SSH)(Tool); 2
StellarParticle(campaign) ; Establish ; Remote Desktop Protocol(RDP) session(Network Traffic); 2
StellarParticle(campaign) ; Use ; VPNs(Tool); 2
[Rewritten CTI articles]
Please extract the security triplets in the articles below:
""").strip()
#[articles]
#[Output]
#Extracted triplets are: [Cyber threat behavior triplets]

# Esta función lanza la petición al modelo para extraer tripletas del texto de cada táctica.
# El resultado es un string con las tripletas extraídas, siguiendo el formato definido arriba.
def extract_triplets(tactic_paragraphs):
    # Si el texto no está vacío, lo formateo como un artículo
    if tactic_paragraphs.strip():
        articles = f"article 0:\n{tactic_paragraphs.strip()}\n"
    else:
        articles = ""
    # Inserto los artículos en el prompt
    prompt = TRIPLET_PROMPT + articles
    messages = [
        {"role": "system",
         "content": "You are an expert CTI information extractor."},
        {"role": "user",
         "content": prompt}
    ]
    resp = openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        temperature=0.0
    )
    return resp.choices[0].message.content.strip().replace("Here are the extracted security-related triplets from the provided article:\n\n", "").replace("Here are the extracted triplets from the provided article:\n\n", "")
