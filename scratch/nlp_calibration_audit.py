import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.engine.threat_intelligence import CARFFilter, ContrastiveNLPEngine


CASES = [
    ("sea", "Severe maritime disruption: Suez Canal blocked, vessels halted, and port traffic stopped."),
    ("sea", "Normal maritime operations continue with no port congestion or vessel delays."),
    ("air", "Severe airport closure: flights cancelled and air cargo operations suspended."),
    ("air", "Normal airport operations continue with flights and cargo handling on schedule."),
    ("road", "Severe highway closure: truck traffic stopped and the main logistics corridor is blocked."),
    ("road", "Normal highway traffic and delivery operations continue without disruption."),
    ("rail", "Severe rail disruption: tracks are closed and freight services are suspended."),
    ("rail", "Normal rail freight services continue with scheduled operations."),
]


def main():
    nlp = ContrastiveNLPEngine()
    carf = CARFFilter()

    print("mode\tmargin\tsemantic\tcarf\ttext")
    for mode, text in CASES:
        score = nlp.get_semantic_score(text)
        filtered = carf.apply_filter(score, text, mode)
        print(
            f"{mode}\t{nlp.last_margin!r}\t{score:.6f}\t{filtered:.6f}\t{text}"
        )


if __name__ == "__main__":
    main()