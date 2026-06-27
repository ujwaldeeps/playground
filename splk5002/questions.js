/* ================================================================
   SPLK-5002 Question Bank — 60 questions
   window.QUESTIONS is consumed by app.js
   ================================================================ */

window.QUESTIONS = [

  /* ============================================================
     DETECTION ENGINEERING  (12 questions)
     ============================================================ */
  {
    id: "de-001",
    domain: "Detection Engineering",
    question: "In Splunk Enterprise Security, what is the primary purpose of a correlation search?",
    options: [
      "To schedule SPL queries that identify patterns or anomalies across multiple data sources and generate notable events",
      "To import external threat intelligence feeds into the KV store",
      "To normalize raw log data into CIM-compliant field names",
      "To provide a real-time dashboard showing live event counts per sourcetype"
    ],
    correct: 0,
    explanations: [
      "Correct. Correlation searches are scheduled SPL queries that detect conditional patterns across machine data, asset/identity data, and threat intelligence, then generate notable events when conditions are met.",
      "Incorrect. Threat intelligence feeds are managed through the Threat Intelligence Framework and its own lookup-populating searches, not through correlation searches.",
      "Incorrect. CIM normalization is handled at the add-on/sourcetype level via props.conf and transforms.conf — not by correlation searches.",
      "Incorrect. Live event dashboards are built with panels and real-time searches; they are separate from the correlation search framework in ES."
    ]
  },
  {
    id: "de-002",
    domain: "Detection Engineering",
    question: "Risk-Based Alerting (RBA) in Splunk ES shifts detection from point-in-time alerts to behavioral analysis. Which component aggregates low-severity risk events before triggering a high-confidence alert?",
    options: [
      "The Incident Review dashboard",
      "The Risk Index",
      "The Threat Intelligence KV store",
      "The Data Model Acceleration summary"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Incident Review is the analyst triage interface where notable events appear after they have already been created — it does not aggregate risk scores.",
      "Correct. The Risk Index is a central repository that collects incremental risk scores from individual risk events attached to risk objects (users and systems). A risk incident rule fires a notable only when the aggregated risk score crosses a threshold.",
      "Incorrect. The Threat Intelligence KV store holds IOC data (IPs, domains, hashes) and is used to enrich or match events, not to aggregate behavioral risk.",
      "Incorrect. Data model acceleration builds TSIDX summaries to speed up data model searches; it has no role in risk score aggregation."
    ]
  },
  {
    id: "de-003",
    domain: "Detection Engineering",
    question: "An analyst wants to prevent a noisy correlation search from firing repeatedly for the same source IP within a 24-hour window. Which correlation search setting should be configured?",
    options: [
      "Cron schedule",
      "Throttling",
      "Notable event suppression",
      "Search acceleration"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The cron schedule controls how often the search runs, but does not prevent duplicate notable events from being created for the same entity once the search fires.",
      "Correct. Throttling in a correlation search lets you specify a field (e.g., src_ip) and a time window during which a second match against the same field value will not generate an additional notable event, directly reducing duplicate alerting.",
      "Incorrect. Notable event suppression is an ES feature that hides already-created notable events from the Incident Review queue; it does not prevent the correlation search from creating new ones.",
      "Incorrect. Search acceleration improves query performance using TSIDX summaries but has no effect on how many notable events are generated."
    ]
  },
  {
    id: "de-004",
    domain: "Detection Engineering",
    question: "Which Splunk ES feature provides over 1,600 pre-built, MITRE ATT&CK-mapped detections that are regularly updated by Splunk's Threat Research Team?",
    options: [
      "Detection Studio",
      "Enterprise Security Content Update (ESCU)",
      "Risk Analysis adaptive response action",
      "Splunk App for MITRE ATT&CK"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Detection Studio is the workflow interface within ES for creating, testing, and deploying custom detections; it does not ship pre-built content.",
      "Correct. ESCU (Enterprise Security Content Update) is a Splunk-maintained app delivering 1,600+ production-ready detections, analytic stories, and supporting content all mapped to MITRE ATT&CK.",
      "Incorrect. The Risk Analysis adaptive response action attaches risk scores to risk objects when a detection fires; it is not a content library.",
      "Incorrect. While Splunk offers MITRE ATT&CK visualization tools, the primary source of pre-built, maintained detections is ESCU."
    ]
  },
  {
    id: "de-005",
    domain: "Detection Engineering",
    question: "In the Detection Studio workflow, what is the correct order of phases in the detection lifecycle?",
    options: [
      "Deploy → Test → Plan → Monitor",
      "Plan → Develop → Test → Deploy → Monitor",
      "Develop → Plan → Deploy → Test → Monitor",
      "Test → Plan → Develop → Monitor → Deploy"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Deploying before testing would push unvalidated detections into production, which is a best-practice violation.",
      "Correct. Detection Studio follows: Plan (define requirements, map to MITRE ATT&CK) → Develop (write the SPL) → Test (validate against real data in isolation) → Deploy (promote to production) → Monitor (track performance via the Launchpad).",
      "Incorrect. Planning must occur before development; deploying before testing is also incorrect.",
      "Incorrect. Testing before planning and developing is illogical; monitoring comes after deployment."
    ]
  },
  {
    id: "de-006",
    domain: "Detection Engineering",
    question: "A scheduled correlation search runs every 5 minutes. To avoid missing events that span run intervals, what time range configuration is recommended?",
    options: [
      "earliest=-5m latest=now",
      "earliest=-65m@m latest=-5m@m",
      "earliest=-1h latest=now",
      "earliest=@d latest=now"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Using latest=now can miss events that have not yet been indexed; it also provides no overlap buffer to catch late-arriving events.",
      "Correct. earliest=-65m@m latest=-5m@m provides a 1-hour lookback window with a 5-minute offset to account for indexing lag, plus an overlap buffer so that events near the boundary of the previous run are not missed.",
      "Incorrect. earliest=-1h latest=now provides no safe offset for indexing lag and uses a real-time latest, which is unreliable for scheduled searches.",
      "Incorrect. earliest=@d resets to midnight, which produces extremely variable search windows and is inappropriate for high-frequency scheduled detections."
    ]
  },
  {
    id: "de-007",
    domain: "Detection Engineering",
    question: "Which SPL command is best suited for correlating a sequence of events from the same user into a single grouped transaction for detection purposes?",
    options: [
      "stats count BY user",
      "transaction user maxspan=1h",
      "eval result=mvappend(events)",
      "lookup user_lookup user OUTPUT risk_score"
    ],
    correct: 1,
    explanations: [
      "Incorrect. stats count BY user counts events per user but does not group them into temporal sequences or preserve individual event details within the group.",
      "Correct. The transaction command groups consecutive events sharing a field value (e.g., user) into a single event, with maxspan limiting how far apart in time events can be. This is ideal for detecting multi-step attack sequences.",
      "Incorrect. eval with mvappend can build multivalue fields but does not group raw events temporally into transactions.",
      "Incorrect. The lookup command enriches events with data from an external table; it does not correlate sequential events."
    ]
  },
  {
    id: "de-008",
    domain: "Detection Engineering",
    question: "When onboarding threat intelligence into Splunk ES, where are parsed IOC indicators stored so they can be matched against live events?",
    options: [
      "In the main index as threat_activity events",
      "In KV store collections with an _intel suffix",
      "In the summary index as pre-computed lookups",
      "In the assets_by_str KV store collection"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The threat_activity index stores matches after a threat has been detected — it is the output of matching, not the storage location of the raw IOCs.",
      "Correct. The Threat Intelligence Framework parses feed data and stores IOC collections in KV store with names ending in _intel (e.g., ip_intel, domain_intel). These are used as lookups during threat generation searches.",
      "Incorrect. Summary indexes store pre-computed results from report acceleration; they are not used to store threat intelligence.",
      "Incorrect. assets_by_str is part of the Asset & Identity framework for storing asset metadata; it is unrelated to threat intelligence IOCs."
    ]
  },
  {
    id: "de-009",
    domain: "Detection Engineering",
    question: "An ESCU detection is grouped with related detections that tell a complete attack narrative. What is this grouping called?",
    options: [
      "Detection Pack",
      "Analytic Story",
      "Correlation Bundle",
      "Threat Profile"
    ],
    correct: 1,
    explanations: [
      "Incorrect. 'Detection Pack' is not a term used in ESCU or Splunk ES. It may appear in other vendor products but not in this context.",
      "Correct. An Analytic Story is the ESCU concept for grouping related detections, investigations, and context around a specific threat (e.g., 'Cobalt Strike', 'Ransomware') to provide a complete attack narrative.",
      "Incorrect. 'Correlation Bundle' is not a defined term in Splunk ES or ESCU.",
      "Incorrect. 'Threat Profile' is a general security term but is not the name for grouped ESCU content."
    ]
  },
  {
    id: "de-010",
    domain: "Detection Engineering",
    question: "In Risk-Based Alerting, a risk notable event is generated when which condition is met?",
    options: [
      "Any individual correlation search fires against a risk object",
      "The aggregated risk score for a risk object exceeds the threshold defined in a risk incident rule",
      "A risk object appears in more than three different data sources within one hour",
      "The risk object is found in the threat intelligence KV store"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Individual correlation searches add risk scores to the Risk Index but do not directly create notable events in RBA — that is the job of risk incident rules.",
      "Correct. Risk incident rules evaluate aggregated risk scores in the Risk Index. When a risk object's total score crosses the configured threshold, the risk incident rule fires and creates a risk notable event in Incident Review.",
      "Incorrect. The number of contributing data sources does not directly trigger a risk notable; only the threshold-crossing rule does.",
      "Incorrect. Presence in the threat intelligence KV store may contribute risk points via a TI-matching correlation search, but by itself does not create a risk notable."
    ]
  },
  {
    id: "de-011",
    domain: "Detection Engineering",
    question: "Which SPL command should be used to add asset or identity context to events during a detection search without writing data permanently to an index?",
    options: [
      "inputlookup",
      "lookup",
      "outputlookup",
      "collect"
    ],
    correct: 1,
    explanations: [
      "Incorrect. inputlookup reads an entire lookup file as a dataset into search results; it does not enrich events on a per-event basis using a join-like field match.",
      "Correct. The lookup command enriches each event in the pipeline by matching a field value against a lookup table (such as the asset or identity lookup) and appending matching fields — all in memory without writing to any index.",
      "Incorrect. outputlookup writes search results into a lookup file; it would overwrite the asset table rather than reading from it.",
      "Incorrect. collect writes events to a summary index for storage; it does not enrich events with external context data."
    ]
  },
  {
    id: "de-012",
    domain: "Detection Engineering",
    question: "The Launchpad dashboard in Detection Studio provides which primary capability to a detection engineer?",
    options: [
      "Real-time SPL query editing and syntax validation",
      "Visibility into detection coverage mapped to MITRE ATT&CK and monitoring of detection health",
      "Management of KV store collections used by threat intelligence",
      "Configuration of data model acceleration schedules"
    ],
    correct: 1,
    explanations: [
      "Incorrect. SPL editing and syntax validation happen within the individual detection edit view, not on the Launchpad.",
      "Correct. The Launchpad is the Detection Studio overview dashboard that shows which MITRE ATT&CK tactics and techniques are covered, the health and status of deployed detections, and gaps in coverage.",
      "Incorrect. KV store collection management is done through the ES Configuration menu or REST API, not the Launchpad.",
      "Incorrect. Data model acceleration is configured under Settings → Data Model Acceleration, not through Detection Studio."
    ]
  },

  /* ============================================================
     SECURITY PROCESSES AND PROGRAMS  (6 questions)
     ============================================================ */
  {
    id: "sp-001",
    domain: "Security Processes and Programs",
    question: "An analyst is triaging a notable event in Splunk ES Incident Review and needs to assign ownership and track investigation steps. Which built-in workflow supports this?",
    options: [
      "The Threat Intelligence workbench",
      "The notable event owner, status, and urgency fields on the Incident Review panel",
      "The Detection Studio test panel",
      "The Risk Analysis dashboard"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The Threat Intelligence workbench is used to manage IOC feeds and lookups; it is not an incident triage workflow tool.",
      "Correct. Incident Review allows analysts to assign a notable event an owner, update its status (New, In Progress, Resolved, etc.), set urgency, and add investigation comments — all within the ES workflow.",
      "Incorrect. The Detection Studio test panel is used to validate detection logic before deployment; it is not designed for post-alert investigation.",
      "Incorrect. The Risk Analysis dashboard shows aggregated risk scores and contributing events; it is a visibility tool, not an investigation workflow tracker."
    ]
  },
  {
    id: "sp-002",
    domain: "Security Processes and Programs",
    question: "A security team wants to map their deployed Splunk ES correlation searches to the MITRE ATT&CK framework to identify coverage gaps. Which feature natively supports this mapping?",
    options: [
      "CIM data model tagging",
      "ESCU analytic stories and the Detection Studio MITRE ATT&CK coverage view",
      "The ES Content Management saved search list",
      "The Forwarder Audit dashboard"
    ],
    correct: 1,
    explanations: [
      "Incorrect. CIM data model tagging classifies event types (authentication, network_traffic, etc.) for normalization purposes; it does not map detections to ATT&CK techniques.",
      "Correct. ESCU ships detections pre-mapped to MITRE ATT&CK tactics and techniques. Detection Studio's Launchpad surfaces this mapping visually, showing which techniques have coverage and which are gaps.",
      "Incorrect. The ES Content Management page lists installed content but does not provide an ATT&CK heat-map or gap analysis view.",
      "Incorrect. The Forwarder Audit dashboard tracks data pipeline health, not security coverage mapping."
    ]
  },
  {
    id: "sp-003",
    domain: "Security Processes and Programs",
    question: "In a hypothesis-driven threat hunt using Splunk, what is the correct first step?",
    options: [
      "Run broad SPL searches across all indexes to find anomalies",
      "Formulate a specific hypothesis about adversary behavior based on threat intelligence or known TTPs",
      "Enable all ESCU detections to maximize coverage before starting",
      "Create a new index to store hunt results before executing any search"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Running broad, undirected searches without a hypothesis is reactive exploration, not a structured threat hunt methodology. It is inefficient and produces low signal.",
      "Correct. The hypothesis-driven methodology starts by forming a specific, testable hypothesis (e.g., 'Attackers are using living-off-the-land binaries to move laterally') based on threat intelligence or ATT&CK TTPs before writing any search.",
      "Incorrect. Enabling all detections is a defensive posture change, not a threat hunt. Many detections may be noisy or irrelevant to the hunt objective.",
      "Incorrect. Creating a storage index before the hunt begins is premature; index creation decisions should be based on what data the hunt actually produces."
    ]
  },
  {
    id: "sp-004",
    domain: "Security Processes and Programs",
    question: "Which industry framework does Splunk ES natively integrate with to provide a structured taxonomy of adversary tactics, techniques, and procedures (TTPs)?",
    options: [
      "OWASP Top 10",
      "NIST Cybersecurity Framework",
      "MITRE ATT&CK",
      "ISO 27001"
    ],
    correct: 2,
    explanations: [
      "Incorrect. OWASP Top 10 focuses on web application security vulnerabilities and is not integrated into the Splunk ES detection framework.",
      "Incorrect. While NIST CSF informs organizational security programs, Splunk ES does not natively map detections to NIST CSF categories in its out-of-the-box content.",
      "Correct. Splunk ES and ESCU natively tag detections with MITRE ATT&CK tactic and technique IDs, and Detection Studio provides a visual ATT&CK matrix showing coverage.",
      "Incorrect. ISO 27001 is an information security management system standard; Splunk ES does not ship with ISO 27001 control mappings natively."
    ]
  },
  {
    id: "sp-005",
    domain: "Security Processes and Programs",
    question: "A Tier-1 SOC analyst receives a notable event in Incident Review. After initial triage, they determine it needs deeper investigation. What is the appropriate next action within Splunk ES?",
    options: [
      "Suppress the notable event to remove it from the queue",
      "Escalate by reassigning ownership to a Tier-2 analyst and changing the status to 'In Progress'",
      "Delete the underlying raw events from the index",
      "Disable the correlation search that generated the notable"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Suppressing a notable event hides it from Incident Review without investigation — appropriate only for confirmed false positives, not for events requiring deeper analysis.",
      "Correct. The standard escalation workflow in ES Incident Review is to update the owner field to assign to the appropriate analyst, update the status to In Progress, and add investigation notes before handing off.",
      "Incorrect. Deleting raw events from Splunk indexes is not possible through the standard ES interface (and would violate data retention and forensic integrity).",
      "Incorrect. Disabling the correlation search would prevent future detections of this type for all users — an inappropriate action during the investigation of a single event."
    ]
  },
  {
    id: "sp-006",
    domain: "Security Processes and Programs",
    question: "Which Splunk ES component stores enriched information about hosts and users (e.g., business unit, priority, location) used to provide context during investigations?",
    options: [
      "The Risk Index",
      "The Asset and Identity framework",
      "The Threat Intelligence KV store",
      "CIM data model lookups"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The Risk Index stores risk events (risk scores associated with risk objects); it does not store descriptive asset or identity metadata.",
      "Correct. The Asset and Identity framework in Splunk ES maintains lookup tables containing enriched metadata about hosts and users — such as owner, priority, business unit, and location — which is automatically joined to notable events to provide investigation context.",
      "Incorrect. The Threat Intelligence KV store holds IOC data (malicious IPs, domains, hashes); it does not hold internal asset/identity metadata.",
      "Incorrect. CIM data model lookups normalize event field names and values; they do not store asset context about internal hosts and users."
    ]
  },

  /* ============================================================
     AUTOMATION AND EFFICIENCY  (6 questions)
     ============================================================ */
  {
    id: "ae-001",
    domain: "Automation and Efficiency",
    question: "What is the key advantage of using Splunk SOAR playbooks for incident response compared to manual analyst workflows?",
    options: [
      "Playbooks permanently store raw log events in a dedicated SOAR index for faster retrieval",
      "Playbooks execute response actions at machine speed, reducing mean time to respond (MTTR) and eliminating repetitive manual tasks",
      "Playbooks replace the need for correlation searches in Splunk ES",
      "Playbooks automatically tune detection thresholds based on analyst feedback"
    ],
    correct: 1,
    explanations: [
      "Incorrect. SOAR playbooks orchestrate actions across systems; they do not function as a log storage mechanism.",
      "Correct. The primary advantage of SOAR playbooks is speed and consistency: automated actions (enrichment, containment, notification) execute in seconds versus minutes or hours manually, directly reducing MTTR and freeing analysts for higher-value work.",
      "Incorrect. Correlation searches remain the detection layer in Splunk ES; SOAR playbooks handle response after a detection fires. They are complementary, not interchangeable.",
      "Incorrect. Detection threshold tuning is a manual or ML-assisted process in ES; playbooks are not designed to adjust correlation search parameters automatically."
    ]
  },
  {
    id: "ae-002",
    domain: "Automation and Efficiency",
    question: "In Splunk Enterprise Security, an Adaptive Response action is configured to run when a correlation search fires. Which built-in action assigns a risk score to a risk object at the time of detection?",
    options: [
      "Create Notable Event",
      "Email action",
      "Risk Analysis",
      "Run Script"
    ],
    correct: 2,
    explanations: [
      "Incorrect. 'Create Notable Event' generates a triage item in Incident Review but does not add a risk score to the Risk Index.",
      "Incorrect. The email action sends a notification message; it does not interact with the Risk Index.",
      "Correct. The Risk Analysis adaptive response action attaches a risk score and risk object metadata to the Risk Index when a correlation search fires, enabling RBA workflows to aggregate behavioral risk over time.",
      "Incorrect. 'Run Script' executes a custom shell or Python script; it can be configured to do anything but is not the purpose-built action for risk scoring."
    ]
  },
  {
    id: "ae-003",
    domain: "Automation and Efficiency",
    question: "A Splunk SOAR playbook needs to block a malicious IP on a perimeter firewall automatically. Which playbook component handles the connection to the external firewall system?",
    options: [
      "A decision block",
      "An App action using a firewall connector",
      "A filter block",
      "A format block"
    ],
    correct: 1,
    explanations: [
      "Incorrect. A decision block is a logical branching element (if/else) that routes playbook execution based on conditions; it does not communicate with external systems.",
      "Correct. SOAR App actions use pre-built connectors (apps) for specific technology integrations. A firewall app (e.g., Palo Alto, Check Point) exposes actions like 'block IP' that the playbook calls to execute containment on the external device.",
      "Incorrect. A filter block selects a subset of items from an action's output to pass to the next step; it does not invoke external integrations.",
      "Incorrect. A format block builds formatted strings (e.g., email bodies, ticket descriptions) from playbook data; it does not execute actions on external systems."
    ]
  },
  {
    id: "ae-004",
    domain: "Automation and Efficiency",
    question: "Which Python library is provided by Splunk ES to help developers create custom Adaptive Response actions that interact with the CIM and notable events?",
    options: [
      "splunklib",
      "cim_actions.py",
      "phantom_sdk",
      "rest_client.py"
    ],
    correct: 1,
    explanations: [
      "Incorrect. splunklib is the Splunk Python SDK used for general Splunk REST API interactions; it is not specifically designed for building ES Adaptive Response actions.",
      "Correct. cim_actions.py is the Splunk ES-provided library specifically designed for custom Adaptive Response action development. It includes helper classes for creating notable events, adding risk scores, and other ES-specific actions.",
      "Incorrect. phantom_sdk is associated with Splunk SOAR (formerly Phantom) app development, not ES Adaptive Response actions.",
      "Incorrect. rest_client.py is a generic term; it is not the designated library for ES Adaptive Response development."
    ]
  },
  {
    id: "ae-005",
    domain: "Automation and Efficiency",
    question: "A Splunk SOAR playbook enriches a suspicious IP address by querying a threat intelligence service, then routes execution differently based on whether the IP is malicious. Which playbook block type implements this routing logic?",
    options: [
      "Action block",
      "Decision block",
      "Format block",
      "Start block"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Action blocks call App actions (e.g., query a threat intel API); they execute operations but do not contain conditional routing logic.",
      "Correct. A Decision block evaluates conditions (e.g., 'if reputation score > 80 then route to containment, else route to monitoring') and branches playbook execution accordingly based on the results of prior actions.",
      "Incorrect. A Format block constructs formatted strings from playbook data; it does not branch execution.",
      "Incorrect. The Start block is the entry point of every playbook; there is only one and it does not contain conditional logic."
    ]
  },
  {
    id: "ae-006",
    domain: "Automation and Efficiency",
    question: "When integrating Splunk ES with Splunk SOAR, how are notable events typically passed from ES to SOAR to trigger playbook execution?",
    options: [
      "By writing notable events to a shared summary index that SOAR polls",
      "Via the Splunk ES Adaptive Response action that sends the notable event to SOAR as a new container",
      "By exporting notable events as CSV files to a shared file system",
      "SOAR reads directly from the notable index using a scheduled SPL search"
    ],
    correct: 1,
    explanations: [
      "Incorrect. While SOAR can ingest data from Splunk indexes, the standard integration for notable events is the Adaptive Response / SOAR action, not a polling mechanism on a summary index.",
      "Correct. The standard ES-to-SOAR integration uses an Adaptive Response action (the Splunk SOAR action) configured on a correlation search. When the search fires, it automatically sends the notable event details to SOAR as a new container, triggering associated playbooks.",
      "Incorrect. CSV export workflows are a manual, non-real-time integration method not used in a production ES/SOAR deployment.",
      "Incorrect. While SOAR can query Splunk directly for additional data, the primary triggering mechanism for notable-event-driven playbooks is the Adaptive Response action push, not a SOAR-side scheduled query."
    ]
  },

  /* ============================================================
     DATA ENGINEERING  (3 questions)
     ============================================================ */
  {
    id: "deng-001",
    domain: "Data Engineering",
    question: "A security team wants to use CIM-based data models for correlation searches but is experiencing slow search performance. Which feature should be enabled to pre-compute and store data model results for faster search-time access?",
    options: [
      "Field extraction with TRANSFORMS",
      "Data model acceleration",
      "Summary indexing via collect",
      "Index-time field extraction"
    ],
    correct: 1,
    explanations: [
      "Incorrect. TRANSFORMS-based field extraction improves the accuracy and structure of parsed fields; it does not pre-compute data model results to improve query performance.",
      "Correct. Data model acceleration builds TSIDX (time-series index) summaries of data model results on a schedule, allowing subsequent searches against that data model to use pre-computed summaries rather than scanning raw events, dramatically improving performance.",
      "Incorrect. Summary indexing via the collect command can store computed results but is not the standard mechanism for accelerating CIM data models in Splunk ES.",
      "Incorrect. Index-time field extraction stores extracted fields in the index alongside raw events; while it speeds up some searches, it is not the designated method for accelerating CIM data models."
    ]
  },
  {
    id: "deng-002",
    domain: "Data Engineering",
    question: "A new log source has field names that differ from CIM standards (e.g., the source IP field is named 'client_address' instead of 'src'). Which configuration file approach is used to map 'client_address' to the CIM field 'src' without re-indexing?",
    options: [
      "Add a field alias in props.conf mapping client_address to src",
      "Edit the raw events in the index to rename the field",
      "Create a lookup table mapping client_address values to src values",
      "Modify the data model definition to accept client_address as an alias"
    ],
    correct: 0,
    explanations: [
      "Correct. Field aliases defined in props.conf (FIELDALIAS stanzas) tell Splunk to treat an existing field name as another name at search time — making client_address available as src without reindexing or modifying raw data. This is the standard CIM compliance technique.",
      "Incorrect. Raw events in a Splunk index cannot be edited after ingestion; this is a fundamental architectural constraint.",
      "Incorrect. A lookup table maps field values (e.g., IP addresses) to additional attributes; it cannot rename a field name itself.",
      "Incorrect. Data model definitions describe which events are included and which fields are expected; the correct normalization approach is field aliasing at the sourcetype level, not modifying the data model."
    ]
  },
  {
    id: "deng-003",
    domain: "Data Engineering",
    question: "An organization needs to collect Windows Event Logs from 500 endpoints and forward them to a Splunk indexer cluster. Which Splunk component should be deployed on each endpoint?",
    options: [
      "Heavy Forwarder",
      "Universal Forwarder",
      "Search Head",
      "Deployment Server"
    ],
    correct: 1,
    explanations: [
      "Incorrect. A Heavy Forwarder is a full Splunk instance that can parse, filter, and route data before forwarding; deploying it on 500 endpoints would be resource-intensive and unnecessary for standard log forwarding.",
      "Correct. The Universal Forwarder (UF) is a lightweight agent designed specifically for endpoint deployment. It collects and forwards raw data to indexers with minimal CPU and memory footprint, making it the standard choice for large-scale endpoint collection.",
      "Incorrect. A Search Head provides the user interface and search capabilities; it does not collect endpoint data and should never be deployed on monitored endpoints.",
      "Incorrect. A Deployment Server manages configuration distribution to forwarders; it is a management plane component, not a data collection agent."
    ]
  },

  /* ============================================================
     AUDITING AND REPORTING  (3 questions)
     ============================================================ */
  {
    id: "ar-001",
    domain: "Auditing and Reporting",
    question: "A SOC manager wants to review the activity of their analysts in Splunk ES Incident Review — specifically which analysts closed the most notable events and how long events remained open. Which built-in dashboard provides this information?",
    options: [
      "The Forwarder Audit dashboard",
      "The Incident Review Audit dashboard",
      "The Indexing Audit dashboard",
      "The Risk Analysis dashboard"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The Forwarder Audit dashboard tracks the health and connectivity of data forwarders; it contains no analyst activity metrics.",
      "Correct. The Incident Review Audit dashboard in Splunk ES tracks analyst actions on notable events — including ownership changes, status transitions, resolution times, and per-analyst workload statistics.",
      "Incorrect. The Indexing Audit dashboard monitors data ingestion volumes (Events Per Day) and index performance; it does not track analyst behavior.",
      "Incorrect. The Risk Analysis dashboard surfaces risk score distributions and contributing events for risk objects; it is an investigation tool, not an analyst performance tracker."
    ]
  },
  {
    id: "ar-002",
    domain: "Auditing and Reporting",
    question: "A compliance team needs to demonstrate that Splunk is successfully collecting logs from all critical firewall and IDS systems. Which Splunk ES dashboard should they review?",
    options: [
      "Incident Review Audit",
      "Risk Analysis",
      "Forwarder Audit",
      "Detection Studio Launchpad"
    ],
    correct: 2,
    explanations: [
      "Incorrect. The Incident Review Audit dashboard tracks analyst triage activity on notable events, not the health of data sources.",
      "Incorrect. Risk Analysis shows behavioral risk scoring information; it does not report on whether data sources are actively sending logs.",
      "Correct. The Forwarder Audit dashboard reports on the status of all Splunk Universal and Heavy Forwarders, showing which hosts are actively sending data, last contact time, and data volumes — directly answering whether critical log sources are feeding Splunk.",
      "Incorrect. The Detection Studio Launchpad shows detection coverage gaps against MITRE ATT&CK; it does not report on data pipeline health."
    ]
  },
  {
    id: "ar-003",
    domain: "Auditing and Reporting",
    question: "Which metric does the Splunk ES Indexing Audit dashboard use to track data ingestion volume over time?",
    options: [
      "Mean Time to Detect (MTTD)",
      "Events Per Day (EPD)",
      "Risk Score Delta",
      "Notable Event Close Rate"
    ],
    correct: 1,
    explanations: [
      "Incorrect. MTTD (Mean Time to Detect) is a security operations KPI measuring detection latency; it is tracked in SOC reporting, not in the Indexing Audit dashboard.",
      "Correct. The Indexing Audit dashboard in Splunk ES uses Events Per Day (EPD) as its primary metric to track indexing rates and trends, helping administrators identify data source drops or ingestion anomalies.",
      "Incorrect. Risk Score Delta measures changes in risk object scores over time; it is part of RBA reporting, not indexing auditing.",
      "Incorrect. Notable Event Close Rate is an analyst performance and IR efficiency metric tracked in Incident Review Audit, not the Indexing Audit dashboard."
    ]
  },


  /* ============================================================
     DETECTION ENGINEERING  (questions 13–24)
     ============================================================ */
  {
    id: "de-013",
    domain: "Detection Engineering",
    question: "Which Splunk ES data model provides the foundation for detecting authentication-based attacks such as brute-force and credential stuffing?",
    options: [
      "Network Traffic data model",
      "Authentication data model",
      "Endpoint data model",
      "Web data model"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The Network Traffic data model covers connection-level data (src/dest IPs, ports, bytes); it does not normalize authentication events like login successes and failures.",
      "Correct. The Authentication CIM data model normalizes fields such as user, src, dest, action (success/failure), and app across all authentication log sources (Windows Security, VPN, cloud IdP), making it the foundation for brute-force and credential-based detections.",
      "Incorrect. The Endpoint data model covers processes, filesystem changes, registry, and services on hosts — not authentication events.",
      "Incorrect. The Web data model covers HTTP request/response data from proxies and web servers, not authentication events."
    ]
  },
  {
    id: "de-014",
    domain: "Detection Engineering",
    question: "A detection engineer wants to identify machines communicating with known malicious IPs by joining live network events against a threat intelligence lookup. Which SPL pattern correctly implements this?",
    options: [
      "index=network | lookup ip_intel dest_ip OUTPUT threat_category | where isnotnull(threat_category)",
      "index=network | join dest_ip [search index=threat_intel]",
      "index=network | eval is_malicious=if(dest_ip IN (\"1.2.3.4\"), 1, 0)",
      "index=network | inputlookup ip_intel | stats count BY dest_ip"
    ],
    correct: 0,
    explanations: [
      "Correct. Using the lookup command against the ip_intel KV store collection (populated by the Threat Intelligence Framework) and filtering for non-null threat_category is the standard, performant pattern for IOC matching in Splunk ES.",
      "Incorrect. A subsearch join is less efficient and does not leverage the optimized KV store collections maintained by the TI Framework. It also requires the threat intel data to be in a Splunk index rather than a KV store.",
      "Incorrect. Hard-coding IPs with eval is a maintenance anti-pattern; it does not scale and does not benefit from the continuously updated threat intelligence KV store.",
      "Incorrect. inputlookup reads the entire lookup table as the result set — it does not join against live network events per-event."
    ]
  },
  {
    id: "de-015",
    domain: "Detection Engineering",
    question: "When configuring a correlation search in Splunk ES, what does the 'Throttle' field period setting control?",
    options: [
      "How frequently the correlation search SPL query is run on the scheduler",
      "The time window during which a second match for the same field value will not generate a new notable event",
      "The maximum number of results returned by the search before it is truncated",
      "The lookback window for the search's time range"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The search frequency is controlled by the cron schedule field, not the throttle period.",
      "Correct. The throttle period specifies a suppression window per unique field value (e.g., per src_ip). If the same field value triggers the correlation search again within that window, no new notable event is created, preventing duplicate alert fatigue.",
      "Incorrect. Result truncation is controlled by the 'maxresults' setting in savedsearches.conf, not the throttle configuration.",
      "Incorrect. The time range (earliest/latest) is set separately in the search string or the time range fields of the correlation search editor."
    ]
  },
  {
    id: "de-016",
    domain: "Detection Engineering",
    question: "In Splunk Enterprise Security 7+, what is the purpose of the 'Mission Control' interface?",
    options: [
      "A code editor for writing and testing SPL correlation searches",
      "A unified workspace for managing risk notables, investigations, and response actions in a single pane",
      "A configuration panel for setting up data model acceleration schedules",
      "A dashboard for monitoring Universal Forwarder connectivity"
    ],
    correct: 1,
    explanations: [
      "Incorrect. SPL is written and tested in the search bar or Detection Studio, not Mission Control.",
      "Correct. Mission Control is the modern ES interface that consolidates risk notables, related events, investigation timelines, and adaptive response actions into a single analyst workspace, replacing the need to navigate multiple dashboards.",
      "Incorrect. Data model acceleration is managed under Settings, not Mission Control.",
      "Incorrect. Forwarder monitoring is handled by the Forwarder Audit dashboard, not Mission Control."
    ]
  },
  {
    id: "de-017",
    domain: "Detection Engineering",
    question: "A detection generates too many false positives because it fires for an internal vulnerability scanner. What is the best practice resolution?",
    options: [
      "Disable the correlation search permanently",
      "Add the scanner's IP to a lookup-based allowlist and filter it out within the correlation search",
      "Increase the search frequency so the scanner traffic is spread across more executions",
      "Delete the scanner's events from the index"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Disabling the search removes detection coverage for the entire use case for all sources — an overly broad action for a specific known false positive.",
      "Correct. The best practice is to maintain an allowlist (e.g., a KV store or CSV lookup of known scanners/trusted IPs) and add a NOT lookup or where clause to exclude those entries without removing the detection for other sources.",
      "Incorrect. Increasing frequency makes the problem worse — more executions against the same data means more false positive notables, not fewer.",
      "Incorrect. Deleting events from a Splunk index is not possible through standard means, violates data integrity, and is never an appropriate approach to tuning."
    ]
  },
  {
    id: "de-018",
    domain: "Detection Engineering",
    question: "Which SPL command calculates summary statistics (e.g., average, standard deviation) across all events and appends those values back to each individual event without collapsing the result set?",
    options: [
      "stats",
      "eventstats",
      "chart",
      "streamstats"
    ],
    correct: 1,
    explanations: [
      "Incorrect. stats collapses the result set to one row per group — individual events are lost, so you cannot compare each event to the group statistic afterward.",
      "Correct. eventstats computes aggregate statistics and appends them as new fields to every original event in the pipeline, preserving the full event list. This is ideal for anomaly detection (e.g., flagging events where count > avg + 2*stdev).",
      "Incorrect. chart creates a visualization-oriented tabular result grouped by time or another field; it also collapses the result set.",
      "Incorrect. streamstats calculates running/cumulative statistics per event in order, useful for time-ordered analysis but not for global aggregate comparison across all events."
    ]
  },
  {
    id: "de-019",
    domain: "Detection Engineering",
    question: "What is an 'Analytic Story' in the context of ESCU, and why is it useful to a detection engineer?",
    options: [
      "A saved SPL search template for building custom detections from scratch",
      "A curated collection of detections, investigations, and contextual guidance grouped around a specific threat, enabling a complete response workflow",
      "A MITRE ATT&CK technique description imported from the ATT&CK Navigator",
      "A scheduled report that summarizes notable event trends over the past 30 days"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Analytic Stories are pre-built threat content packages, not blank templates for custom development.",
      "Correct. An Analytic Story bundles related detection searches, investigation queries, and supporting documentation around a specific threat (e.g., 'Ransomware', 'Cobalt Strike'). This gives detection engineers and analysts everything needed to detect, investigate, and respond to that threat without building from scratch.",
      "Incorrect. While ESCU maps to MITRE ATT&CK, Analytic Stories are Splunk's own content packaging concept, not imported ATT&CK descriptions.",
      "Incorrect. Scheduled trend reports are separate dashboard or search artifacts; they are not what ESCU Analytic Stories represent."
    ]
  },
  {
    id: "de-020",
    domain: "Detection Engineering",
    question: "In the risk score model used by Splunk ES Risk-Based Alerting, what are the two primary types of risk objects?",
    options: [
      "IP address and domain name",
      "User and system (host)",
      "Sourcetype and index",
      "Tactic and technique"
    ],
    correct: 1,
    explanations: [
      "Incorrect. While IP addresses and domains are common indicators, they are not the two primary risk object types in RBA. RBA focuses on internal entities, not external IOCs.",
      "Correct. In Splunk ES RBA, risk objects are primarily Users (identity-based risk) and Systems/Hosts (asset-based risk). Risk scores accumulate against these two entity types, enabling behavioral profiling of internal accounts and machines.",
      "Incorrect. Sourcetype and index are data pipeline concepts, not entities that accumulate behavioral risk in RBA.",
      "Incorrect. Tactic and technique are MITRE ATT&CK classification labels used to tag detections; they are not risk objects that accumulate risk scores."
    ]
  },
  {
    id: "de-021",
    domain: "Detection Engineering",
    question: "Which setting in a Splunk ES correlation search controls the minimum number of results that must be returned before the search will trigger an alert?",
    options: [
      "Throttle field",
      "Alert condition threshold",
      "Cron expression",
      "Search acceleration"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The throttle field controls the suppression window for duplicate notables per entity, not the minimum result count needed to fire.",
      "Correct. The alert condition (e.g., 'Number of Results is greater than 0', or a custom condition like 'results > 5') defines the threshold the search output must meet before a notable event is generated.",
      "Incorrect. The cron expression sets when the search runs on a schedule; it has no effect on what result count triggers an alert.",
      "Incorrect. Search acceleration improves query performance; it does not control when an alert is triggered."
    ]
  },
  {
    id: "de-022",
    domain: "Detection Engineering",
    question: "A detection engineer needs to compare a user's current login time against their historical baseline to detect anomalous access hours. Which Splunk capability is most appropriate?",
    options: [
      "A single correlation search using stats count BY user",
      "Splunk Machine Learning Toolkit (MLTK) to build a baseline model and detect deviations",
      "A lookup table listing every acceptable login hour per user",
      "Configuring alert throttling to 24 hours"
    ],
    correct: 1,
    explanations: [
      "Incorrect. A simple stats count BY user aggregates logins but cannot establish a behavioral baseline or identify what hours are anomalous for a specific user.",
      "Correct. The Machine Learning Toolkit provides algorithms (e.g., DensityFunction, OneClassSVM) to build per-user baselines of normal activity and score deviations at detection time, making it the right tool for behavioral anomaly detection like abnormal login hours.",
      "Incorrect. Maintaining a static lookup table per user and hour would require constant manual updates, cannot adapt to changing behavior patterns, and is unscalable for a large organization.",
      "Incorrect. Throttling controls duplicate alert suppression; it has no capability to compare current behavior against a historical baseline."
    ]
  },
  {
    id: "de-023",
    domain: "Detection Engineering",
    question: "When a new ESCU content update is installed in Splunk ES, what is the recommended next step before enabling new detections in production?",
    options: [
      "Immediately enable all new detections to maximize coverage",
      "Review the detections in Detection Studio, test them against production data, and tune thresholds before enabling",
      "Export the detections to a CSV and send them to the security team for email review",
      "Restart the Splunk ES search head to apply the new content"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Enabling all detections without review will flood Incident Review with untested, potentially noisy alerts that are not tuned to the specific environment.",
      "Correct. Best practice is to review new ESCU content in Detection Studio, run test panel validations against real data, assess false positive rates, and tune thresholds before promoting detections to production.",
      "Incorrect. Exporting to CSV for email review bypasses the built-in Detection Studio workflow and introduces delays without adding value.",
      "Incorrect. ESCU content is installed as a Splunk app and applied via the UI; a search head restart is not required and would interrupt other analyst activity."
    ]
  },
  {
    id: "de-024",
    domain: "Detection Engineering",
    question: "Which field, present on every notable event in Splunk ES, provides the analyst with a normalized measure of how urgently the event needs attention, derived from severity and asset/identity priority?",
    options: [
      "risk_score",
      "urgency",
      "priority",
      "confidence"
    ],
    correct: 1,
    explanations: [
      "Incorrect. risk_score is the cumulative value in the Risk Index associated with a risk object; it is not a per-notable urgency field derived from asset priority.",
      "Correct. The urgency field on a notable event is automatically calculated by combining the correlation search's configured severity with the priority of the matched asset or identity from the Asset & Identity framework (e.g., a 'high' severity alert on a 'critical' asset yields 'critical' urgency).",
      "Incorrect. priority is an attribute of assets in the Asset & Identity lookup; it is an input to the urgency calculation, not the final urgency field itself.",
      "Incorrect. confidence is a field used in some threat intelligence and risk frameworks to indicate how reliable a signal is; it is not the ES urgency field that drives analyst prioritization."
    ]
  },

  /* ============================================================
     SECURITY PROCESSES AND PROGRAMS  (questions 7–12)
     ============================================================ */
  {
    id: "sp-007",
    domain: "Security Processes and Programs",
    question: "A SOC analyst uses the Splunk ES Incident Review 'Investigate' action on a notable event. What is the primary benefit of this action?",
    options: [
      "It automatically runs all ESCU detections against the event's source IP",
      "It opens a contextual investigation workbench linking related events, assets, and identities to the notable",
      "It sends the notable event to Splunk SOAR to trigger a playbook",
      "It generates a PDF report of the notable event for compliance purposes"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The Investigate action does not re-run detection searches; it pivots into an investigation context built around the existing notable event's artifacts.",
      "Correct. The Investigate action in ES opens an investigation workbench that surfaces correlated events, asset/identity context, timeline views, and related notables — allowing the analyst to build a complete picture without manually crafting separate searches.",
      "Incorrect. Sending to SOAR is handled by a configured Adaptive Response action, not the native Investigate button in Incident Review.",
      "Incorrect. PDF report generation is not a function of the Investigate action; reporting is done via scheduled reports or the audit dashboards."
    ]
  },
  {
    id: "sp-008",
    domain: "Security Processes and Programs",
    question: "The Lockheed Martin Cyber Kill Chain is referenced alongside MITRE ATT&CK in Splunk ES threat modeling. Which Kill Chain phase does 'Command and Control (C2)' correspond to?",
    options: [
      "Reconnaissance",
      "Exploitation",
      "Command and Control",
      "Actions on Objectives"
    ],
    correct: 2,
    explanations: [
      "Incorrect. Reconnaissance is the first Kill Chain phase where the adversary researches the target; it occurs long before C2 is established.",
      "Incorrect. Exploitation is the phase where the adversary leverages a vulnerability to gain an initial foothold; C2 is established after this phase.",
      "Correct. Command and Control is its own phase in the Lockheed Martin Kill Chain, occurring after installation. The adversary establishes a covert channel back to their infrastructure to maintain persistence and direct further actions.",
      "Incorrect. Actions on Objectives is the final Kill Chain phase where the adversary achieves their goal (e.g., data exfiltration, destruction); it requires C2 to already be in place."
    ]
  },
  {
    id: "sp-009",
    domain: "Security Processes and Programs",
    question: "What distinguishes proactive threat hunting from reactive incident response in a Splunk ES environment?",
    options: [
      "Threat hunting uses automated playbooks; incident response is manual",
      "Threat hunting searches for unknown threats not yet detected by existing correlation searches; incident response investigates already-fired alerts",
      "Threat hunting only uses the Risk Index; incident response only uses Incident Review",
      "Threat hunting requires ESCU; incident response does not"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Both threat hunting and incident response can use automation. The key distinction is not the tooling but the posture — proactive vs. reactive.",
      "Correct. Threat hunting is proactive: analysts form hypotheses and search for indicators of compromise or attacker behavior that existing detections have not yet caught. Incident response is reactive: it is triggered by an alert or confirmed event that has already been detected.",
      "Incorrect. Both activities may involve the Risk Index and Incident Review. There is no such strict division of which Splunk component each activity uses.",
      "Incorrect. Both threat hunting and incident response can be performed with or without ESCU. ESCU provides pre-built detections, which are useful but not required for either activity."
    ]
  },
  {
    id: "sp-010",
    domain: "Security Processes and Programs",
    question: "A security engineer is defining escalation paths for the SOC. At what point should a Tier-1 analyst escalate a notable event to Tier-2?",
    options: [
      "Immediately upon receiving any notable event with severity above 'low'",
      "When the initial triage determines the event cannot be resolved with standard runbooks and requires deeper forensic investigation",
      "Only when the event has been open for more than 72 hours",
      "When the event affects more than 10 hosts simultaneously"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Escalating all medium+ severity events to Tier-2 would overwhelm Tier-2 analysts with events that Tier-1 can resolve using standard runbooks, defeating the purpose of tiered SOC structure.",
      "Correct. The appropriate escalation trigger is when Tier-1 exhausts their standard runbook and the investigation requires specialized forensic skills, deeper context analysis, or non-standard response actions — not based on a fixed time or host count threshold.",
      "Incorrect. Waiting 72 hours to escalate introduces unacceptable dwell time for genuine incidents. Time-based escalation should be a backstop, not the primary criterion.",
      "Incorrect. The number of affected hosts is one factor that may increase urgency, but scope alone does not determine whether a Tier-2 escalation is needed if Tier-1 runbooks cover the scenario."
    ]
  },
  {
    id: "sp-011",
    domain: "Security Processes and Programs",
    question: "In Splunk ES, notable event suppression is configured. What is the key risk of suppressing notable events without careful governance?",
    options: [
      "It increases indexing load on the Splunk environment",
      "Legitimate security incidents may be hidden from analysts, creating blind spots",
      "It slows the performance of the underlying correlation search",
      "It prevents ESCU content from being updated"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Suppression is a UI-layer filter on Incident Review; it has no effect on indexing load or search performance.",
      "Correct. Suppression hides matching notable events from Incident Review. If suppression rules are too broad or remain in place indefinitely, real incidents matching those criteria will silently disappear from analyst queues — a significant detection blind spot.",
      "Incorrect. Suppression rules are evaluated at display time in Incident Review and do not affect the execution performance of correlation searches.",
      "Incorrect. ESCU updates are managed independently through the app installation mechanism; suppression rules have no relationship to content update schedules."
    ]
  },
  {
    id: "sp-012",
    domain: "Security Processes and Programs",
    question: "Which MITRE ATT&CK tactic represents the adversary's effort to maintain a foothold in the environment after initial access?",
    options: [
      "Initial Access",
      "Persistence",
      "Lateral Movement",
      "Exfiltration"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Initial Access (TA0001) covers the techniques used to gain the very first foothold; it precedes the need for persistence.",
      "Correct. Persistence (TA0003) covers techniques adversaries use to maintain their foothold across restarts, credential changes, and other interruptions — such as registry run keys, scheduled tasks, and implanted backdoors.",
      "Incorrect. Lateral Movement (TA0008) describes techniques for pivoting to other systems within the network after already having a foothold; it is a distinct tactic from establishing persistence.",
      "Incorrect. Exfiltration (TA0010) covers techniques for stealing data from the target environment; it is typically a late-stage tactic after persistence has already been established."
    ]
  },

  /* ============================================================
     AUTOMATION AND EFFICIENCY  (questions 7–12)
     ============================================================ */
  {
    id: "ae-007",
    domain: "Automation and Efficiency",
    question: "In Splunk SOAR, what is the purpose of a 'Prompt' block in a playbook?",
    options: [
      "To automatically enrich an event with threat intelligence without analyst interaction",
      "To pause playbook execution and require an analyst to provide input or make a decision before continuing",
      "To send a formatted notification email to the security team",
      "To query the Splunk search head for additional event data"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Automated enrichment is handled by App action blocks that query threat intelligence services without pausing for human input.",
      "Correct. A Prompt block pauses the playbook and presents a question or choice to a human analyst via the SOAR interface or email. Execution resumes only after the analyst responds, enabling human-in-the-loop decision making for high-stakes actions like blocking production systems.",
      "Incorrect. Sending email notifications is an action block using an email app connector, not a Prompt block.",
      "Incorrect. Querying Splunk for additional event data is an App action block using the Splunk connector; it does not require analyst input."
    ]
  },
  {
    id: "ae-008",
    domain: "Automation and Efficiency",
    question: "A SOAR playbook is designed to automatically contain a compromised endpoint. Which sequence of automated actions follows security best practices?",
    options: [
      "Isolate endpoint → collect forensic artifacts → notify analyst → create ticket",
      "Create ticket → notify analyst → isolate endpoint → collect forensic artifacts",
      "Delete all processes → reimage endpoint → notify analyst",
      "Notify analyst → wait 24 hours → isolate endpoint"
    ],
    correct: 0,
    explanations: [
      "Correct. Isolating the endpoint first stops the threat from spreading (containment), then collecting forensic artifacts preserves evidence before any remediation, then notifying the analyst and creating a ticket maintains the audit trail — following the Contain → Eradicate → Recover IR sequence.",
      "Incorrect. Creating a ticket first delays containment. The longer an endpoint remains active and connected, the greater the risk of lateral movement or data exfiltration.",
      "Incorrect. Deleting processes and reimaging without collecting forensic artifacts first destroys evidence needed to understand the full scope of the compromise.",
      "Incorrect. Waiting 24 hours to isolate is operationally dangerous — an actively compromised endpoint can cause significant additional damage in that time window."
    ]
  },
  {
    id: "ae-009",
    domain: "Automation and Efficiency",
    question: "Which Splunk SOAR feature allows an analyst to manually trigger a playbook against a specific event container from the event details page?",
    options: [
      "Scheduled playbook execution",
      "On-demand playbook execution",
      "Automated label-based routing",
      "Passive playbook mode"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Scheduled execution runs playbooks on a time-based schedule, not triggered by an analyst on a specific event.",
      "Correct. On-demand execution lets an analyst select and run any playbook manually from within an event container, enabling ad-hoc response actions on specific cases without waiting for automated triggers.",
      "Incorrect. Label-based routing automatically routes new containers to playbooks based on matching labels; it is not analyst-triggered.",
      "Incorrect. Passive mode is not a standard SOAR execution mode in this context; it does not describe manual analyst-triggered execution."
    ]
  },
  {
    id: "ae-010",
    domain: "Automation and Efficiency",
    question: "A Splunk ES correlation search generates a notable event, and an Adaptive Response action is configured to run automatically. What determines whether the action runs immediately when the search fires vs. requiring analyst approval?",
    options: [
      "Whether the correlation search uses the Risk Analysis or Create Notable Event action",
      "Whether the Adaptive Response action is configured as 'Automatic' or 'Recommended'",
      "The urgency level of the resulting notable event",
      "The time of day the correlation search fires"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The type of action (Risk Analysis vs. Create Notable) determines what the action does, not whether it requires approval.",
      "Correct. Adaptive Response actions can be set as 'Automatic' (runs immediately when the search fires without analyst interaction) or 'Recommended' (appears as a suggested action on the notable event that an analyst must manually trigger). This setting controls the human-in-the-loop behavior.",
      "Incorrect. Urgency influences how the notable event is prioritized in Incident Review but does not control automatic vs. recommended execution of response actions.",
      "Incorrect. The execution mode of an Adaptive Response action is static configuration; the time of day has no effect on whether analyst approval is required."
    ]
  },
  {
    id: "ae-011",
    domain: "Automation and Efficiency",
    question: "In Splunk SOAR playbook development, which block type is used to iterate over a list of IOCs returned from a previous action and process each one individually?",
    options: [
      "Decision block",
      "Custom function block with a loop",
      "Filter block",
      "Format block"
    ],
    correct: 1,
    explanations: [
      "Incorrect. A Decision block evaluates conditions and branches; it does not iterate over collections of items.",
      "Correct. A Custom Function block allows writing Python code that can loop over a list (e.g., iterate over multiple IP addresses returned from a threat intel lookup) and process each item individually, enabling per-item logic within a playbook.",
      "Incorrect. A Filter block narrows down a list based on criteria (e.g., keep only results where reputation > 80) but does not iterate over each item to execute subsequent actions per item.",
      "Incorrect. A Format block builds formatted strings from playbook data; it does not provide iteration logic."
    ]
  },
  {
    id: "ae-012",
    domain: "Automation and Efficiency",
    question: "What is the advantage of using the Splunk REST API within a SOAR playbook for querying Splunk data, compared to simply reading events from the SOAR container?",
    options: [
      "The REST API is faster because it bypasses the SOAR event container entirely",
      "The REST API allows the playbook to run ad-hoc SPL searches against the Splunk index for additional context not already in the container",
      "The REST API automatically normalizes all data to CIM before returning results",
      "The REST API is the only way to trigger Splunk ES correlation searches from SOAR"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Speed is not the primary advantage; the container holds the event data already passed from ES. The REST API's value is in accessing additional data beyond what the container contains.",
      "Correct. The SOAR event container holds the fields from the originating notable event, which may be limited. Using the Splunk REST API connector in a playbook, analysts can run arbitrary SPL searches to pull supplementary context (e.g., full authentication history for a user) directly from Splunk indexes at response time.",
      "Incorrect. The REST API returns raw Splunk search results; CIM normalization happens at the add-on/props layer during indexing, not via the API itself.",
      "Incorrect. Correlation searches in ES run on their configured schedules or can be triggered via the ES API; SOAR does not use the REST API specifically to trigger them."
    ]
  },

  /* ============================================================
     DATA ENGINEERING  (questions 4–6)
     ============================================================ */
  {
    id: "deng-004",
    domain: "Data Engineering",
    question: "A sourcetype's raw events contain a timestamp in the format 'DD/MMM/YYYY:HH:MM:SS'. The events are being indexed with incorrect timestamps. Which configuration file and stanza type should be modified to fix this?",
    options: [
      "transforms.conf — REGEX stanza",
      "props.conf — TIME_FORMAT stanza",
      "inputs.conf — index stanza",
      "outputs.conf — tcpout stanza"
    ],
    correct: 1,
    explanations: [
      "Incorrect. transforms.conf REGEX stanzas are used for field extractions and event routing; they do not control how Splunk parses timestamp formats.",
      "Correct. props.conf controls sourcetype-level parsing behavior. The TIME_FORMAT stanza (e.g., TIME_FORMAT = %d/%b/%Y:%H:%M:%S) tells Splunk exactly how to parse the timestamp in raw events, resolving incorrect index-time timestamp assignment.",
      "Incorrect. inputs.conf configures data input sources (file monitors, network ports); it does not contain timestamp parsing instructions.",
      "Incorrect. outputs.conf configures where a forwarder sends data; it has no role in timestamp parsing."
    ]
  },
  {
    id: "deng-005",
    domain: "Data Engineering",
    question: "What is the primary purpose of a Heavy Forwarder compared to a Universal Forwarder in a Splunk data collection architecture?",
    options: [
      "A Heavy Forwarder uses less memory and CPU, making it suitable for endpoint deployment",
      "A Heavy Forwarder can parse, filter, mask, and route data before forwarding, enabling data transformation at the collection tier",
      "A Heavy Forwarder stores a local copy of all forwarded data as a backup",
      "A Heavy Forwarder is required when collecting Windows Event Logs from domain controllers"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The Universal Forwarder is the lightweight agent with minimal resource footprint; the Heavy Forwarder runs a full Splunk instance and uses significantly more resources.",
      "Correct. A Heavy Forwarder runs a full Splunk instance, allowing it to perform index-time parsing, field extractions, event filtering, data masking (e.g., PII), and intelligent routing to different indexes or indexers before forwarding — capabilities the Universal Forwarder lacks.",
      "Incorrect. Neither forwarder type stores a persistent local copy of forwarded data as a backup; data persistence is the responsibility of the indexer tier.",
      "Incorrect. Universal Forwarders are commonly used to collect Windows Event Logs from domain controllers and other Windows hosts. A Heavy Forwarder is not required for this."
    ]
  },
  {
    id: "deng-006",
    domain: "Data Engineering",
    question: "A CIM data model search is running slowly despite data model acceleration being enabled. Which of the following is a likely cause?",
    options: [
      "The data model acceleration summary has not yet been built for the relevant time range",
      "The CIM add-on is not installed on the search head",
      "The correlation search is using the wrong cron schedule",
      "The Universal Forwarders are not sending data fast enough"
    ],
    correct: 0,
    explanations: [
      "Correct. Data model acceleration builds TSIDX summaries on a schedule (default: every 10 minutes, with a build delay). For historical time ranges not yet covered by the summary — such as periods before acceleration was enabled or gaps due to schedule delays — searches fall back to scanning raw events, causing slow performance.",
      "Incorrect. The CIM add-on provides data model definitions and field normalizations; its absence would cause normalization failures, not slow acceleration performance once the model is already accelerated.",
      "Incorrect. The cron schedule of a correlation search affects when detection runs; it does not impact the performance of data model summary builds.",
      "Incorrect. Forwarder throughput affects data ingestion latency into the index; once data is indexed, search performance depends on TSIDX summary availability, not forwarder speed."
    ]
  },

  /* ============================================================
     AUDITING AND REPORTING  (questions 4–6)
     ============================================================ */
  {
    id: "ar-004",
    domain: "Auditing and Reporting",
    question: "A security manager wants to track how many notable events were suppressed over the past month and identify which suppression rules are responsible. Which Splunk ES dashboard provides this visibility?",
    options: [
      "Incident Review Audit dashboard",
      "Suppression Audit dashboard",
      "Risk Analysis dashboard",
      "Indexing Audit dashboard"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The Incident Review Audit dashboard tracks analyst actions (status changes, ownership assignments) on visible notable events; it does not report on suppressed events that never appeared in the queue.",
      "Correct. The Suppression Audit dashboard in Splunk ES specifically tracks which suppression rules are active, how many notables each rule has suppressed, and the trend over time — essential for governance of suppression policies.",
      "Incorrect. The Risk Analysis dashboard surfaces risk score information and contributing risk events; it has no reporting capability on suppression rules.",
      "Incorrect. The Indexing Audit dashboard monitors data ingestion volumes and forwarder health; it is unrelated to notable event suppression."
    ]
  },
  {
    id: "ar-005",
    domain: "Auditing and Reporting",
    question: "An executive stakeholder requests a high-level dashboard showing current security posture across business units, with visual indicators for key risk areas. Which Splunk feature is best suited to create this executive-level view?",
    options: [
      "A standard Splunk dashboard panel using a table visualization",
      "A Glass Table in Splunk ES",
      "The Detection Studio Launchpad",
      "The Incident Review queue with custom filters"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Standard table panels can display data but lack the visual hierarchy, custom iconography, and infrastructure topology overlays that executive stakeholders typically need for a security posture view.",
      "Correct. Glass Tables in Splunk ES (also available via ITSI) provide highly customizable, visual-rich dashboards that can overlay KPIs, color-coded status indicators, and live metric values onto custom background images of network diagrams or business unit maps — ideal for executive security posture communication.",
      "Incorrect. The Detection Studio Launchpad is an operational tool for detection engineers to manage coverage gaps and detection health; it is not designed for executive reporting.",
      "Incorrect. The Incident Review queue is an analyst triage tool; presenting it to executive stakeholders would surface operational noise rather than summarized posture metrics."
    ]
  },
  {
    id: "ar-006",
    domain: "Auditing and Reporting",
    question: "A compliance team needs a Splunk ES report demonstrating that all PCI-DSS-relevant log sources (firewalls, IDS, authentication systems) are ingesting data without gaps. Which combination of dashboards best addresses this requirement?",
    options: [
      "Risk Analysis dashboard and Incident Review Audit dashboard",
      "Forwarder Audit dashboard and Indexing Audit dashboard",
      "Detection Studio Launchpad and Suppression Audit dashboard",
      "Incident Review queue and the notable event timeline"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Risk Analysis and Incident Review Audit report on detection activity and analyst behavior respectively; neither confirms that specific log sources are ingesting data continuously.",
      "Correct. The Forwarder Audit dashboard confirms which forwarders (and therefore which log sources) are active and sending data, while the Indexing Audit dashboard shows ingestion volumes and trends over time — together providing evidence that PCI-relevant sources have been continuously feeding Splunk without gaps.",
      "Incorrect. The Detection Studio Launchpad shows ATT&CK coverage gaps in detections; the Suppression Audit shows suppressed notables. Neither confirms log source ingestion continuity for compliance.",
      "Incorrect. The Incident Review queue shows open security alerts; the notable event timeline shows when events were created. Neither provides evidence about data pipeline health for compliance auditing."
    ]
  }

];
