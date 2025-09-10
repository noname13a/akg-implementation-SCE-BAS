import functools, textwrap
from typing import List
import openai
from attackcti import attack_client


# -----------------------------------------------------------------------------
# Construyo la plantilla de las 14 tácticas MITRE directamente desde el
# servidor TAXII. Así siempre tengo las descripciones oficiales y actualizadas.
# Uso lru_cache para no hacer la petición más de una vez por ejecución.
# -----------------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def build_tactic_template():
    """
    Devuelvo un bloque de texto con las 14 tácticas Enterprise, en el orden
    correcto de la kill-chain, y con la descripción oficial (solo el primer
    parrafo para ahorrar tokens). Así el LLM siempre tiene el contexto exacto.
    """
    lift = attack_client()
    enterprise = lift.get_enterprise_tactics() # Obtengo las tácticas Enterpris
    # Filtro solo las tácticas no revocadas
    tactics = [o for o in enterprise if not o.get("revoked", False)]
    # Ordeno las tácticas según el shortname oficial de MITRE
    ordered_shortnames = [
        "reconnaissance", "resource-development", "initial-access", "execution",
        "persistence", "privilege-escalation", "defense-evasion", "credential-access",
        "discovery", "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact"
    ]
    # Construyo el bloque de texto: "Nombre: descripción"
    blocks: List[str] = []
    for short in ordered_shortnames:
        tac = next(t for t in tactics if t["x_mitre_shortname"] == short)
        name = tac["name"]
        # Solo el primer párrafo de la descripción
        description = tac["description"].split("\n")[0].strip()
        blocks.append(f"{name}: {description}")

    return "\n".join(blocks)


# Guardo la plantilla para usarla en el prompt
#TACTIC_TEMPLATE = build_tactic_template()

REWRITE_PROMPT = textwrap.dedent("""
You are an assistant to re-organize the Cyber Threat Intelligence (CTI) report to stage summary according to the tactics in cyber attacks. The definitions of the tactics and
their subordinate technical labels will be provided in the following rules. When providing a summary for each corresponding tactic-level label, please include as much
detailed information as possible about the sub-techniques under the respective tactic-level label (if available in the given CTI report). Your task is based on the following
rules:

[Rules]
Rule 1: Process of section summary: For each tactic, if there is relevant content in the CTI report, extract and rewrite the related content in chronological order as
detailed as possible. If there is no relevant content, skip that tactic and output ‘‘None’’ as the summary. Key information, including the names of entities and the
relationships of relations related to the subordinate techniques for the given tactic, needs to be preserved in the rewriting process.
Rule 2: There are 14 tactics in cyber attacks, and these 14 tactics will be provided, along with their names and corresponding descriptions, in the logical order of cyber
attack:
[Examples]
1. Reconnaissance:The adversary is trying to gather information they can use to plan future operations.Reconnaissance consists of techniques that involve adversaries
actively or passively gathering information that can be used to support targeting. Such information may include details of the victim organization, infrastructure, or
staff/personnel. This information can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using gathered information to plan and
execute Initial Access, to scope and prioritize post-compromise objectives, or to drive and lead further Reconnaissance efforts.
    1. 1 Active Scanning
    1. 2 Gather Victim Host Information
    ......
2. Resource Development:The adversary is trying to establish resources they can use to support operations.Resource Development consists of techniques that involve
adversaries creating, purchasing, or compromising/stealing resources that can be used to support targeting. Such resources include infrastructure, accounts, or capabilities.
These resources can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using purchased domains to support Command and Control,
email accounts for phishing as a part of Initial Access, or stealing code signing certificates to help with Defense Evasion.
    2.1 Acquire Access
    ......
i. [Tactic]:[Description of the Tactic]
    i.1 [Technique in Tactic]
......
Rule 3: The following entity types should be preserved as the key information as much as possible when rewriting: ‘‘[Entities]’’
Rule 4: The following relation types should be preserved as the key information as much as possible when rewriting: ‘‘[Relations]’’
Rule 5: If you believe that the CTI report contains some other highly important information that does not fall under the aforementioned 14 tactics categories, please
extract and rewrite the relevant content in chronological order and place it under the ‘Others’ label. Additionally, in the output, place the ‘Others’ label after all the
tactics categories.

[CTI Report]
Please rewrite the CTI Report according to the rules above:

""").strip()
#[CTI Report]
#[Output]
#The rewritten result of the report is: [Rewritten cyber threat intelligence report]

def rewrite(report_txt):
    """
    Reescribe el informe CTI agrupándolo por táctica MITRE.
    """
    #prompt = REWRITE_PROMPT.format(
        #tactic_defs=TACTIC_TEMPLATE,
    #    cti_report=report_txt
    #)
    prompt = REWRITE_PROMPT + report_txt
    messages = [
        {
            "role": "system",
            "content": "You are a cybersecurity analyst specialised in MITRE ATT&CK."
        },
        {
            "role": "user",
            "content": prompt
        }
    ]
    response = openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        temperature=0.1
    )
    return response.choices[0].message.content.strip()
