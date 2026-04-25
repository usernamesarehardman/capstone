# Project Report: Tor Website Fingerprinting
**Data Traffic Engineering & Systems Analysis**

## 👤 Role & Responsibility

**Current Role:** Data Traffic Engineer (formerly Systems Engineer)

*   **Context:** Swapped roles to take ownership of traffic collection, dataset integrity, and pipeline remediation.
*   **Focus:** Automating data collection, vetting website lists, and analyzing traffic pattern drift.

## 🛠 Technical Stack

*   **Environment:** VMWare Ubuntu VM
*   **Automation:** Selenium WebDriver + Geckodriver
*   **Browser:** Firefox (Tor-enabled)
*   **Methodology:** Headless driver configuration (specifically requesting headed traffic) to bypass basic bot-detection algorithms.

## 📈 Project Evolution (Phases)

### Phase 1: Early Project & Initial Collection

*   **Objective:** Establish a baseline dataset using Alexa’s Top 100.
*   **Scope:** 100 traces per 50 websites.
*   **Initial Findings:** ML Training accuracy (Top-1) ranged from 40%–50%.
*   **Analysis:** Identified anomalies in the confusion matrix. Many websites returned only 50-100 packets, indicating that the automation was hitting CAPTCHAs or bot-verification pages instead of the intended content.

### Phase 2: Remediation & Quality Control

*   **Strategy:** Shifted focus from quantity to data quality ("Breadth over Depth").
*   **Actions:**
    *   Vetted the website pool to remove Cloudflare/CAPTCHA-heavy sites.
    *   Added ~30 more websites with 50 traces each.
*   **Refined Scope:** 40–49 hand-picked websites.
*   **Results:** Accuracy improved to ~60% Top-1 confidence.

### Phase 3: Experimentation & Failure Analysis

*   **Challenge:** Testing real-time inference via a GUI revealed high confusion and inaccurate guesses.
*   **Hypotheses:**
    1.  Trace volume was insufficient for robust training.
    2.  **Website Drift:** Traffic patterns changed as websites updated.
*   **Attempted Fix:** Tried parallelizing Tor data collection to increase volume.
*   **Outcome:** Parallelization increased network noise significantly, rendering the resulting data unreadable for the model.

### Phase 4: Final Affirmations

*   **Validation:** Verified a vetted list of 49 websites that are not blocked by Cloudflare.
*   **Final Accuracy:** Maintained 50%–60% Top-1 accuracy, with Top-5 reaching 80%.
*   **Discovery:** Confirmed that dynamic front-page elements cause rapid drift, though high-traffic sites like Google and DuckDuckGo remain relatively predictable.

## 🔍 Key Findings & Future Research

> [!IMPORTANT]
> **Identified Obstacles**
>
> *   **GUI Integration:** Real-time parsing struggles with data consistency compared to batch training.
> *   **Website Drift:** The "static" assumption is flawed; modern UI/backend updates change fingerprints over time.
> *   **Volume Gaps:** Current trace amounts are a bottleneck for model performance.

### Proposed Research Paths

*   **Trace Optimization:** Mathematical analysis to determine the ideal trace counts for both Classical ML and Deep Learning.
*   **Drift Resilience:** Researching how to identify "invariant" traffic patterns that remain constant despite front-end UI changes.
