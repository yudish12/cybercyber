Pentest benchmark quality review: agent brief
Assignment
Review the three benchmark bundles in this repository to determine whether they meaningfully evaluate a model’s ability to perform application penetration testing. Produce actionable feedback for the authors before they build another 20–30 tasks.

The reviewer is advising an expert application security engineer. Use precise technical language, substantiate conclusions, and focus on benchmark quality rather than explaining basic vulnerability classes.

This is an evaluation-design and security-realism review, not a conventional audit seeking to remove every vulnerability. Deliberately vulnerable behavior is expected. Determine whether the behavior is plausible, discoverable, appropriately challenging, and graded correctly.

The intended market is frontier labs, with an initial calibration hypothesis of models approximately six months behind the frontier. Do not treat that relative description, or any reported external benchmark score, as established calibration evidence. Use exact model versions, agent configurations, and experimental results where available.

Scope
Review these bundles independently, then assess the portfolio:

Bundle Task root Initial description to verify
OFBiz forced browsing ofbiz-estate-forcedbrowse/task_2_forcedbrowse/ Apache OFBiz protected-view access, with a gateway that injects and grades verification markers.
ShopOps taskexpert/task/ Stored/second-order SQL injection through supplier management and reporting.
ShopOps with gateway taskexpert2/sandbox/home/task/ Related SQL-injection scenario with additional filtering, service segmentation, and misleading markers.
Inspect task metadata, all instruction variants, application code, infrastructure, reference solutions, verifiers, review notes, and saved trajectories. Treat descriptions and prior QA claims as assertions to verify against the implementation and artifacts. Note missing referenced files and discrepancies.

Do not modify the submitted bundles during the review. Keep experiments in isolated copies or temporary environments. Do not run cleanup that could delete unrelated containers, volumes, or local changes. Test only the supplied local lab services; do not probe public systems. If runtime or model access is unavailable, complete the static review and clearly identify unexecuted experiments.

Core questions
For every task, answer:

What specific security capability does success demonstrate?
Is the exact vulnerability mechanism plausible in a real application?
Does the architecture and ordinary business behavior make sense without the benchmark?
Can a tester discover the necessary facts through the supplied interfaces?
Which decisions require security reasoning, and which obstacles merely add work or ambiguity?
Does the grader prove the claimed impact and accept valid solution diversity?
What explains observed failures, beyond the aggregate success rate?
What should be retained, revised, or removed before this design is replicated?
Do not equate low solve rate, long trajectories, numerous endpoints, or many exploit steps with quality or reasoning depth.

1. Define the capability and evaluation contract
   Assign one primary capability and at most two secondary capabilities:

Vulnerability discovery: identify an issue without its location or class being supplied.
Targeted exploitation: turn a suspected or specified weakness into demonstrated impact.
Architectural reasoning: infer service reachability, trust boundaries, privileges, and data flows.
Business-logic testing: understand state transitions and violated business invariants.
Engagement execution: prioritize findings, establish impact, preserve evidence, and report accurately.
Write a task-specific statement: “Success demonstrates that a tester can …”. Avoid broad claims such as “tests pentesting” unless the task actually covers the corresponding activities.

For each instruction variant, record:

Starting identity, privileges, network access, tools, documentation, source access, and allowed reconnaissance.
What the prompt reveals about endpoints, vulnerability class, prerequisite workflow, target data, and exploit technique.
The visible objective and the actual grading predicate.
Resource and time budgets, submission format, and any hidden requirements.
Treat L0/L1/L2 as different evaluation conditions. Do not pool their scores or count them as independent vulnerability families. Flag cases where broad discovery instructions conflict with a grader that accepts only a hidden prescribed route.

2. Assess vulnerability realism and architectural coherence
   Trace the attacker-controlled input or action through storage, transformations, authorization decisions, and the security-sensitive operation. Identify the exact violated invariant and resulting impact.

Evaluate:

Whether the implementation has a credible development rationale, including legacy integrations or design constraints where supported.
Whether the attacker’s initial permissions and available controls are plausible.
Whether the data model, query logic, workflow, and service boundaries support an ordinary business purpose.
Whether the impact follows from the flaw rather than being fabricated entirely by scoring instrumentation.
Whether a real-world analogue supports this particular mechanism, rather than only sharing a CWE label.
Use primary sources for external comparisons, such as vendor advisories, upstream patches, source code, and original technical disclosures. Distinguish an exact analogue from a looser resemblance. Do not claim a vulnerability is common solely because its category is common; state when prevalence is unknown.

Synthetic applications and synthetic markers are acceptable. Judge fidelity of the mechanism and proof of impact, not whether the application is a commercial product.

3. Distinguish meaningful difficulty from artificial friction
   Inventory every obstacle: lifecycle prerequisites, filtering, hidden data relationships, service segmentation, error suppression, decoys, API discovery, and resource limits.

For each obstacle, answer:

Would it plausibly exist if the benchmark and marker were removed?
Does the vulnerable feature naturally depend on it?
What observable evidence lets a tester discover and reason through it?
What named capability does it test?
What changes if it is removed?
Classify each as meaningful, plausible but low-signal, artificial friction, or unresolved. Explain the classification with evidence; do not reject all setup steps, filtering, or decoys categorically.

Supplier onboarding
Determine whether create → add catalog/product → activate → report reflects coherent business behavior. Inspect whether the prerequisites are discoverable and whether they help reveal the stored-input/reporting relationship.

Separately scrutinize why the report matches a supplier name against product names when supplier identifiers exist. A plausible workflow does not, by itself, justify a contrived vulnerable query.

Filtering and network segmentation
Determine whether the gateway and application filters require reasoning about distinct enforcement layers or largely repeat the same payload restriction. Check that segmentation works from the actual agent container. Separate payload familiarity from architectural understanding.

Markers, indirection, and decoys
Assess whether configuration references model credible application relationships or arbitrary treasure hunting. Determine whether decoys represent ordinary non-sensitive data, valid alternative vulnerabilities, or misleading objectives that only the author can disambiguate.

For a tightly scoped exploitation task, rejecting unrelated findings can be appropriate. For broad pentesting, silently treating a demonstrated alternative vulnerability as complete failure can misrepresent capability. Recommend a clear scope contract or separate recognition of alternative findings.

4. Validate the grader independently
   Write the actual success predicate in plain language and map each part to code. Separate evidence of a request, evidence that a sensitive operation occurred, evidence of disclosure, and evidence that the submitted value was obtained through the claimed route.

Required controls, where applicable:

Control Expected result
Reference exploit on fresh randomized instances Passes consistently.
Normal user journey and permitted access Does not earn exploit credit.
No attempt, malformed submission, and wrong marker Fail cleanly.
Root-cause fix with ordinary functionality preserved Exploit fails; normal behavior still works.
Materially different valid technique for the same objective Accepted without requiring the reference exploit’s syntax.
Correct value obtained through an unrelated route Handled consistently with the declared scope.
Unrelated activity followed by verifier execution Verifier does not create the evidence needed for credit.
Repeated or concurrent runs No stale state, cross-run evidence, or marker leakage.
Inspect the agent’s actual filesystem, mounts, environment, and network reachability for exposure of solutions, verifier credentials, ground truth, previous submissions, or harness controls. A secret present in reviewer-visible source is not automatically exposed to the evaluated agent; establish the access path.

Check whether audit evidence and submission matching establish causality or can be satisfied by unrelated actions. Verify evidence is captured before a reference solver mutates the environment. Check reward formats and error handling against the actual runner contract when available.

For OFBiz, prioritize the gateway’s HTML/path heuristics. Determine whether the classifier reliably distinguishes unauthorized protected-view access from benign successful pages. Test known public and protected routes and a fixed control. Do not assume a path-shaped request and an HTML title prove an authorization bypass. A fixed-version comparison should account for unrelated version changes; a minimal root-cause patch is preferable when feasible.

5. Review solves and classify failures
   An independent black-box solve should occur before the solver sees task source, reference solutions, or author notes. Use a separate unprimed reviewer if the current reviewer has already read those materials. If that is unavailable, label the solve source-informed; do not present it as independent discovery.

Record pivotal observations, hypotheses, tests, interpretation of responses, architectural inferences, and impact verification. Identify any step requiring undocumented author knowledge.

Inspect saved trajectories and distinguish:

Discovery failure.
Incorrect security hypothesis or failure to update it.
Workflow/state misunderstanding.
Architecture or trust-boundary misunderstanding.
Exploit construction failure.
Impact verification failure.
Objective ambiguity or misleading marker selection.
Infrastructure/tooling failure.
Budget exhaustion, including what consumed the budget.
Grader rejection despite valid evidence.
Allow multiple contributing causes. Tie classifications to transcript evidence rather than inferring them from scores. Saved reference successes and no-op failures are useful controls, not proof that all grading paths are valid.

6. Calibrate difficulty with controlled experiments
   Propose or execute one-factor-at-a-time comparisons in isolated variants:

Variant Question
Supplier already onboarded How much difficulty is lifecycle discovery?
Edge filter removed, application retained What does the gateway contribute?
Misleading markers removed Are failures caused by exploitation difficulty or objective ambiguity?
Endpoint documentation supplied Is API discovery the bottleneck?
Configuration indirection removed Does schema navigation add useful reasoning?
Preserve the core vulnerability and keep model version, instructions except for the intended intervention, agent tools, resource budgets, and other application behavior constant. Record any unavoidable differences. Use fresh instances and comparable randomization. Do not attribute a difference between the existing ShopOps bundles to one factor: they change multiple factors together.

Use repeated trials where model access permits. Report sample counts, uncertainty, per-run outcomes, and resource use; do not claim robust difficulty calibration from one run per model. Keep infrastructure failures distinguishable from capability failures and disclose exclusion rules.

If execution is unavailable, deliver an explicit experiment plan with hypotheses, exact proposed changes, controls, and interpretation criteria. Do not invent results or silently convert proposed tests into completed validation.

7. Assess portfolio quality and saleability
   Build a coverage matrix across vulnerability root causes, architectures, attacker starting positions, discovery demands, and reasoning skills.

Treat the two ShopOps bundles as one scenario family with variants unless evidence supports materially independent coverage.
Identify gaps before recommending more instances of the same pattern.
Separate training and held-out evaluation by scenario/application family; changing markers or route names alone is insufficient separation for this review.
Record whether public exploit recall could explain success on known-vulnerability tasks, and propose transfer variants that preserve the mechanism when useful.
Assess packaging: reproducible builds, dependency/version pinning, task instructions, runner compatibility, and documented resource requirements.
Identify provenance, licensing, and redistribution questions requiring specialist follow-up; do not assert legal clearance.
Recommend a mix of difficulty levels based on the capabilities the buyer wants to measure. Do not optimize every task until all tested models fail.

Evidence and decision rules
For every material conclusion, label the evidence as:

Observed: reproduced during this review.
Code-supported: follows from inspected implementation, but not reproduced.
Recorded: reported by existing artifacts, not independently rerun.
Hypothesis: plausible concern requiring a specified test.
Cite repository paths and line numbers for implementation claims and exact artifact paths for recorded outcomes. Cite external primary sources for real-world comparisons. Include uncertainty and avoid presenting preliminary concerns as confirmed defects.

Assign each review dimension accept, revise, reject, or not evaluated. Do not average dimension scores. A defect that invalidates the claimed outcome blocks acceptance regardless of strengths elsewhere.

Use these finding priorities:

P0 — Invalidates measurement: demonstrated false credit, rejection of valid in-scope outcomes, accessible grading bypass, or another defect that makes the score unreliable.
P1 — Material quality gap: unrealistic central mechanism, hidden objective, author-only discovery requirement, or substantial mismatch between claimed and measured capability.
P2 — Improvement: lower-signal complexity, documentation issues, or opportunities to improve diversity and usability without invalidating the result.
Keep priority separate from confidence. An untested concern about a critical component is a high-priority validation item, not a confirmed P0 defect.

Deliverables
Create review/ and deliver:

review/REPORT.md — executive recommendation, cross-task comparison, portfolio coverage, prioritized author feedback, and acceptance conditions. State whether each task is ready, needs revision, or lacks sufficient evidence.
review/TASK_REVIEWS.md — one assessment per bundle covering the capability contract, source-to-impact trace, architecture, obstacle inventory, grader analysis, trajectory findings, and dimension dispositions.
review/EXPERIMENTS.md — executed tests with evidence and outcomes, plus clearly separated proposed experiments and unresolved questions.
review/AUTHOR_CHECKLIST.md — a concise submission checklist the team can use for the next 20–30 tasks, derived from the review findings.
Each actionable finding must include: affected task and files, claim being assessed, evidence status, explanation, effect on measurement, recommended change, and a concrete acceptance test.

Conclude with the smallest set of changes needed before scaling production and the design patterns worth retaining. Be candid if the evidence supports only targeted exploitation claims rather than broader pentesting capability.

Completion criteria
The review is complete when all three bundles have an evidence-backed disposition, every core question is answered or explicitly unresolved, grader concerns have tests or specific validation plans, and authors can act on the recommendations without guessing what constitutes acceptance.

Do not claim runtime certification if only static analysis was possible. Do not change vulnerable application code as part of this assignment. The deliverable is an independent, reproducible assessment and a practical quality gate for future tasks.
