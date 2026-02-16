# Data & Traffic Engineer — Documentation

This folder holds documentation for the WF-Guard capstone (Data & Traffic Engineer role).

## Capstone-required documentation

| Document | Location | Purpose |
|----------|----------|---------|
| **Data pipeline & reproduction** | [../DATA_PIPELINE.md](../DATA_PIPELINE.md) | How to reproduce the dataset from raw PCAPs; prerequisites, pipeline steps, rebuild instructions. |
| **Design decisions** | [../DESIGN.md](../DESIGN.md) | Interface choice, directory layout, naming convention, labeling scheme, Tor filter. |
| **Task list & deliverables** | [../info.md](../info.md) | Phase breakdown and Week 15 deliverables. |
| **Test checklist** | [../TEST_CHECKLIST.md](../TEST_CHECKLIST.md) | Functional testing checklist for capture, parse, features, and rebuild. |

## In this folder

| Document | Purpose |
|----------|---------|
| [REFERENCES.md](REFERENCES.md) | Public reference links (reference code, datasets) suitable for the project repo. |
| [NOT_IN_REPO.txt](NOT_IN_REPO.txt) | **Do not commit to public repo.** Paper names, private dataset links, and other info you need locally. |

## Quick start

1. Set up environment: see [../DATA_PIPELINE.md#prerequisites](../DATA_PIPELINE.md#prerequisites).
2. Capture traffic: [../capture.py](../capture.py); then parse and build: [../rebuild_dataset.py](../rebuild_dataset.py).
3. Run tests: follow [../TEST_CHECKLIST.md](../TEST_CHECKLIST.md).
