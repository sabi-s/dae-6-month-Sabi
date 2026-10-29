# DAE 6-Month Program — Sabitha S. Karanavar

Coursework and portfolio for a 6-month program focused on **Identity & Access Management (IAM)**, **cybersecurity** and **web development**. Most security reports use a shared healthcare case study, **HVMC**, and the longer-running project is a **Healthcare IAM** implementation built on Microsoft Entra ID and Azure.

**Portfolio site:** <https://sabi-s.github.io/dae-6-month-Sabi/> (built from [`docs/`](docs/))

## Repository layout

### Semesters

| Folder | Contents |
| --- | --- |
| [`Semester_1/`](Semester_1/) | Python projects: `price_tracker/` and `python_1/`, which holds several iterations of the **Smart Deal Alert** app (simple, JSON-backed, multi-user, final) plus `home_destiny_guru.py`. |
| [`Semester_2/`](Semester_2/) | Git/GitHub beginners' guide deck, weekly status updates (weeks 1–4), and Healthcare IAM design documentation and 12-week plan (`WorkforceDevelopmet/`). |
| [`Semester_3/`](Semester_3/) | The Healthcare IAM project: daily work logs, hands-on Entra IAM operations, Week 1 operations, and status updates. |
| [`semester_4/`](semester_4/) | Week 6 status update. |
| [`semester_5/`](semester_5/) | Field Day presentation. |

### Course modules

| Folder | Contents |
| --- | --- |
| [`cloud_security_1/`](cloud_security_1/) | Azure cloud security labs: fundamentals, IAM implementation, architecture and security patterns (incl. HIPAA checklist), compliance and governance, VM/container/serverless hardening, SecOps and incident response with Defender and Sentinel, plus screenshots and a 12-week board. |
| [`cryptography_1/`](cryptography_1/) | Python implementations with demos, tests and saved results: Diffie-Hellman and SHA-256, AES and ChaCha20, RSA and PKI, hashing/HMAC/password hashing, digital signatures and certificate management. One PDF report per topic. |
| [`compliance_1/`](compliance_1/) | Reports on compliance auditing, documentation and reporting, legal and ethical requirements, and the final project. |
| [`cyber_threats_and _vulnerabilities _1/`](cyber_threats_and%20_vulnerabilities%20_1/) | Threat intelligence, vulnerability assessment, malware diagnosis, security monitoring and incident response, and a tabletop IR exercise. |
| [`network_security_ 1/`](network_security_%201/) | Network fundamentals, topology and design, access control, security tools and secure wireless. |
| [`risk_management 1/`](risk_management%201/) | Risk fundamentals, assessment, evaluation and mitigation reports, with workbooks and a risk register. |
| [`design_1/`](design_1/), [`figma_1/`](figma_1/), [`logic_1/`](logic_1/), [`version_control_1/`](version_control_1/), [`unix_1/`](unix_1/), [`unix_2/`](unix_2/) | Smart Deal Alert presentation for each module (Unix folders also include a screenshot). |
| [`markdown_activity/`](markdown_activity/) | Markdown practice (`demo.md`). |
| [`monthly_status_update/`](monthly_status_update/) | Semester 3 monthly status update. |

### Website

| Folder | Contents |
| --- | --- |
| [`docs/`](docs/) | Jekyll portfolio site for GitHub Pages (Minimal Mistakes theme): home, about, projects, resume and contact pages. |
| [`docs_template/`](docs_template/) | The starter template the site was built from. |

## Running the code

The Python projects need Python 3. Some scripts use third-party packages: the cryptography modules use `cryptography`, `bcrypt` and `argon2-cffi`, and the price-tracking scripts use `serpapi` (which reads a SerpApi key from the `SERPAPI_API_KEY` environment variable; never commit the key).

```bash
pip install cryptography bcrypt argon2-cffi serpapi
```

```bash
cd cryptography_1/symmetric_crypto && python3 test_and_demo.py
```

To preview the portfolio site locally (requires Ruby and Bundler):

```bash
cd docs && bundle install && bundle exec jekyll serve
```

## Contact

- GitHub: [sabi-s](https://github.com/sabi-s)
- LinkedIn: [sabithaskaranavar](https://www.linkedin.com/in/sabithaskaranavar/)
