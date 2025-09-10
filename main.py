#!/usr/bin/env python3
import argparse, pathlib, json
import re
import openai
import secrets
from tqdm import tqdm
import rewriter, parser, identifier, summarizer
openai.api_key = secrets.openai_key

def load_report(path: pathlib.Path):
    return path.read_text(encoding="utf-8")

def split_by_tactic(rewritten_txt):
    tactic_blocks = {}
    lines = rewritten_txt.replace("#### ", "").split("\n")
    for line in lines:
        if("Cyber Threat Intelligence Report Summary" in line):
            continue
        else:
            if(re.match(r'^$', line)):
                continue
            else:
                if("Mitigation"  in line or "Impact" in line):
                    return tactic_blocks
                else:
                    if(re.match(r'^\d+\.(\ [a-zA-z]+)+', line) or re.match(r'^Others$', line)):
                        current = line
                    else:
                        #if(current in tactic_blocks.keys()):
                        #    tactic_blocks[current] = tactic_blocks[current].join(line)
                        #else:
                        tactic_blocks[current] = line
    return tactic_blocks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cti_file", type=pathlib.Path, help="Ruta del informe CTI en texto plano")
    ap.add_argument("-o", "--outdir", type=pathlib.Path, default=pathlib.Path("output"))
    args = ap.parse_args()

    args.outdir.mkdir(exist_ok=True)
    report_txt = load_report(args.cti_file)

    print(">> Reescribiendo informe …")
    rewritten = rewriter.rewrite(report_txt)
    (args.outdir / "01_rewritten.txt").write_text(rewritten, encoding="utf-8")

    tactic_blocks = split_by_tactic(rewritten)
    print(tactic_blocks)

    all_triplets, all_tags, all_summaries = {}, {}, {}
    for tactic, block in tqdm(tactic_blocks.items(), desc="Tacticas"):
        print(f"\n--- {tactic} ---\n{block}\n")
        trips = parser.extract_triplets(block)
        all_triplets[tactic] = trips
        tags  = identifier.tag_techniques(trips)
        all_tags[tactic] = tags
        summ = summarizer.summarize_stage(block)
        all_summaries[tactic] = summ

    json.dump(all_triplets,   open(args.outdir / "02_triplets.json",  "w", encoding="utf-8"), indent=2)
    json.dump(all_tags,       open(args.outdir / "03_techniques.json","w", encoding="utf-8"), indent=2)
    json.dump(all_summaries,  open(args.outdir / "04_summary.json",  "w", encoding="utf-8"), indent=2)

if __name__ == "__main__":

    main()
