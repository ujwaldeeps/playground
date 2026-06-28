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
  },

  /* ============================================================
     DETECTION ENGINEERING  (questions 25–36)
     ============================================================ */
  {
    id: "de-025",
    domain: "Detection Engineering",
    question: "Which Splunk Enterprise Security supporting add-on is the primary component responsible for ingesting, parsing, and normalizing external threat intelligence feeds into KV store collections for use in correlation searches?",
    options: [
      "SA-NetworkProtection",
      "SA-ThreatIntelligence",
      "TA-ThreatIntel",
      "SA-ESSIntel"
    ],
    correct: 1,
    explanations: [
      "Incorrect. SA-NetworkProtection provides firewall and network-based detection content for Splunk ES; it does not manage threat intelligence feed ingestion or KV store population.",
      "Correct. SA-ThreatIntelligence is the Splunk ES supporting add-on that downloads, parses, and normalizes threat intelligence feeds, then populates KV store collections such as ip_intel, domain_intel, and file_intel that are queried by threat-generation searches to match against live events.",
      "Incorrect. TA-ThreatIntel is not an official Splunk ES add-on name; it does not exist as a real component in the ES framework.",
      "Incorrect. SA-ESSIntel is not a real Splunk ES add-on name; it is a fictional distractor."
    ]
  },
  {
    id: "de-026",
    domain: "Detection Engineering",
    question: "A detection engineer wants to annotate a correlation search (that does not use the Risk data model) with MITRE ATT&CK technique T1059 so the technique tag appears in Incident Review. What is the correct SPL statement to append at the end of the search?",
    options: [
      "| eval annotations.mitre_attack.mitre_technique_id=\"T1059\"",
      "| eval mitre_attack_id=\"T1059\"",
      "| set annotations.mitre_attack.mitre_technique_id=\"T1059\"",
      "| eval field.mitre_attack.technique=\"T1059\""
    ],
    correct: 0,
    explanations: [
      "Correct. The ES annotation framework recognizes the dot-notation path annotations.mitre_attack.mitre_technique_id when set via eval. Incident Review and Mission Control read this field to display the mapped ATT&CK technique alongside the notable event.",
      "Incorrect. mitre_attack_id is not a recognized ES annotation field; it will not surface the technique in Incident Review because the framework expects the specific annotations.mitre_attack.mitre_technique_id path.",
      "Incorrect. set is not a valid SPL command. The correct command for assigning a field value in the Splunk Processing Language is eval.",
      "Incorrect. The annotation namespace uses annotations.mitre_attack, not field.mitre_attack; this dotted path is not recognized by the ES annotation framework and would create an unrecognized field."
    ]
  },
  {
    id: "de-027",
    domain: "Detection Engineering",
    question: "A security appliance buffers logs during a network outage and forwards them in bulk when connectivity is restored, causing events to arrive at the Splunk indexer hours after they occurred. A correlation search with a 15-minute lookback window misses these events. What is the correct approach to ensure the detection catches them?",
    options: [
      "Increase the search's cron frequency to every 1 minute",
      "Configure the correlation search to use event time (_time) rather than index time, with an appropriately extended lookback window",
      "Enable data model acceleration on the relevant CIM data model",
      "Increase the throttle period to 24 hours"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Increasing cron frequency still applies the lookback window relative to the current clock; events indexed hours late still fall outside the window regardless of how often the search runs.",
      "Correct. Event time (_time) reflects when the event actually occurred, not when it was indexed. By configuring the search time range to use _time and extending the lookback to cover the potential delay window, the detection catches late-arriving events that were generated during the outage but indexed after the normal 15-minute window had passed.",
      "Incorrect. Data model acceleration builds TSIDX summaries to speed up queries; it does not change how the search time window is evaluated or expand coverage to late-arriving events.",
      "Incorrect. The throttle period controls how long duplicate notable events for the same entity are suppressed after one fires; it has no effect on what time range the search covers or whether late-arriving events are detected."
    ]
  },
  {
    id: "de-028",
    domain: "Detection Engineering",
    question: "A detection engineer is building a search to identify brute-force attacks against Active Directory accounts. Which Windows Security Event Code directly indicates that a user account has been locked out due to repeated failed authentication attempts?",
    options: [
      "4624 — An account was successfully logged on",
      "4648 — A logon was attempted using explicit credentials",
      "4740 — A user account was locked out",
      "4776 — The computer attempted to validate the credentials for an account"
    ],
    correct: 2,
    explanations: [
      "Incorrect. Event 4624 records successful authentication events. While useful for detecting successful unauthorized access, it does not indicate account lockout resulting from repeated failures.",
      "Incorrect. Event 4648 records logons using explicitly specified credentials (e.g., RunAs or Pass-the-Ticket); it is not related to account lockout from failed password attempts.",
      "Correct. Windows Security Event 4740 is generated on the domain controller when a user account is locked out due to too many failed authentication attempts. A high count of 4740 events grouped by user is a strong indicator of a brute-force or password spray attack.",
      "Incorrect. Event 4776 records NTLM credential validation attempts on a domain controller; while useful for detecting NTLM-based attacks, it records individual validation attempts and does not directly signal account lockout."
    ]
  },
  {
    id: "de-029",
    domain: "Detection Engineering",
    question: "A CIM-based correlation search is returning results from non-security indexes, adding unwanted noise. The data model is configured and accelerated. Which part of the data model configuration should the engineer review to restrict the search to security-relevant indexes?",
    options: [
      "The data model's dataset hierarchy definition",
      "The data model's constraint macro",
      "The correlation search's alert condition threshold",
      "The Universal Forwarder's inputs.conf monitor stanzas"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The dataset hierarchy defines parent-child relationships between datasets within the model (e.g., Authentication > Default Authentication); it does not control which indexes contribute events to the model.",
      "Correct. The constraint macro in a CIM data model's root event definition (e.g., `cim_authentication_indexes`) contains the index filter that determines which indexed data populates the model. Updating this macro to specify only security-relevant indexes scopes the data model — and all searches derived from it — to the correct data.",
      "Incorrect. The alert condition controls the minimum result count at which a correlation search fires; it does not filter which indexes the underlying search queries.",
      "Incorrect. inputs.conf on Universal Forwarders configures which files or network ports are monitored for data collection; it does not affect how a data model search selects which indexes to query at search time."
    ]
  },
  {
    id: "de-030",
    domain: "Detection Engineering",
    question: "Which SPL command provides the highest query performance when running aggregate statistics against a CIM data model with acceleration enabled in Splunk Enterprise Security?",
    options: [
      "| datamodel Authentication search",
      "| pivot Authentication All_Authentication count",
      "| tstats count FROM datamodel=Authentication WHERE nodename=Authentication BY src",
      "| from datamodel:Authentication.Authentication"
    ],
    correct: 2,
    explanations: [
      "Incorrect. The datamodel command searches the data model but does not take full advantage of the TSIDX acceleration summaries in the same optimized way as tstats; it also returns verbose metadata output.",
      "Incorrect. The pivot command provides a simplified interface and can leverage acceleration, but it generates less flexible SPL and is generally not the preferred option for high-performance aggregate searches in correlation searches.",
      "Correct. tstats directly queries the TSIDX acceleration summaries built by data model acceleration, providing the fastest aggregate search performance (count, sum, dc, etc.) across large datasets. It is the recommended command for CIM-based correlation searches in Splunk ES.",
      "Incorrect. The `from datamodel:` syntax is primarily used in dashboard panels and pivots; tstats remains the preferred and highest-performance command for aggregate queries in production correlation searches."
    ]
  },
  {
    id: "de-031",
    domain: "Detection Engineering",
    question: "In Splunk ES Risk-Based Alerting, what happens to a risk object's accumulated risk score over time without new matching risk events?",
    options: [
      "The score increases automatically based on new threat intelligence feed updates",
      "The score remains permanently until an analyst manually resets it in the Risk Analysis dashboard",
      "The score decays naturally as individual risk events age out of the Risk Index retention window",
      "The score is archived to a summary index after 24 hours to free index space"
    ],
    correct: 2,
    explanations: [
      "Incorrect. Threat intelligence feed updates may trigger new risk events if they match current activity, but they do not increase an existing accumulated score without a corresponding new risk event being generated.",
      "Incorrect. Risk events stored in the Risk Index have a retention period like any other index. As events age out, the aggregated score recalculated by risk incident rules decreases naturally without manual intervention.",
      "Correct. The Risk Index has a configurable retention window. As individual risk events age beyond the retention period, they expire from the index, and the aggregated risk score for the associated risk object decreases proportionally — providing built-in temporal decay that prevents stale activity from indefinitely elevating a risk object's score.",
      "Incorrect. Risk events are not automatically archived to a summary index; they are removed as the index retention window expires, following the same lifecycle as all other Splunk indexed data."
    ]
  },
  {
    id: "de-032",
    domain: "Detection Engineering",
    question: "In Splunk ES Detection Studio, a detection is marked as 'Development' status. What does this mean compared to 'Production' status?",
    options: [
      "'Development' detections run on a real-time schedule; 'Production' detections run on a historical schedule",
      "'Development' detections are visible only to admins; 'Production' detections are visible to all analysts",
      "'Development' detections are being authored or tested and are not yet enabled in production; 'Production' detections are enabled, scheduled, and generating notables in Incident Review",
      "'Development' detections use raw index searches; 'Production' detections require accelerated data models"
    ],
    correct: 2,
    explanations: [
      "Incorrect. The real-time vs. historical distinction refers to the search type, not the content lifecycle status; both 'Development' and 'Production' detections typically use scheduled historical searches.",
      "Incorrect. Content visibility in Detection Studio is controlled by role-based access control, not by the content lifecycle status.",
      "Correct. 'Development' status means the detection is in the authoring, refinement, or testing stage — it is not deployed to the production scheduler and does not generate notable events for analysts. 'Production' status means the detection has been promoted, enabled, and is actively running on its configured cron schedule, generating findings in Incident Review.",
      "Incorrect. The choice of raw vs. accelerated search is determined by the SPL written in the detection, not by its lifecycle status. Both statuses can use either approach."
    ]
  },
  {
    id: "de-033",
    domain: "Detection Engineering",
    question: "When Splunk User Behavior Analytics (UBA) is integrated with Splunk Enterprise Security, what primary type of detection does UBA contribute?",
    options: [
      "Signature-based detections matching known malware file hashes",
      "Rule-based threshold detections counting specific event types per user",
      "Behavioral anomaly detections based on machine learning models of user and entity activity",
      "Real-time packet-level network intrusion detections"
    ],
    correct: 2,
    explanations: [
      "Incorrect. Hash-based malware detection is a signature matching use case handled by Splunk ES threat intelligence against endpoint data; UBA does not perform signature matching.",
      "Incorrect. Rule-based threshold detections are the domain of traditional correlation searches in Splunk ES. UBA's distinct value is its unsupervised machine learning approach that does not rely on predefined thresholds.",
      "Correct. Splunk UBA uses machine learning to build behavioral baselines for users and entities, then identifies statistically significant deviations — such as abnormal login hours, unusual data access volumes, or atypical lateral movement patterns — that rule-based detections would miss. These threats are surfaced as notables in Splunk ES via the UBA integration.",
      "Incorrect. Packet-level network analysis is the domain of network detection tools such as Zeek or Suricata. UBA operates on behavioral metadata (logins, file access, network flows at the session level), not raw packet captures."
    ]
  },
  {
    id: "de-034",
    domain: "Detection Engineering",
    question: "A security team wants to build detections for web application attacks (SQL injection, directory traversal) using web proxy and WAF logs. Which CIM data model should be the foundation for these detections?",
    options: [
      "Network Traffic data model",
      "Authentication data model",
      "Web data model",
      "Intrusion Detection data model"
    ],
    correct: 2,
    explanations: [
      "Incorrect. The Network Traffic data model normalizes connection-level fields (src/dest IP, port, bytes, protocol); it does not include HTTP-specific fields like uri_path, http_method, status codes, or user-agent needed for web attack detections.",
      "Incorrect. The Authentication data model covers login and credential events; it has no relevance to HTTP-level web application attack patterns.",
      "Correct. The CIM Web data model normalizes HTTP traffic fields from proxies, WAFs, and web servers — including url, uri_path, http_method, http_user_agent, status, bytes_in, bytes_out — making it the correct foundation for detecting web application attacks like SQL injection and directory traversal.",
      "Incorrect. The Intrusion Detection data model normalizes IDS/IPS alert events (signatures, categories, severity); while it may capture some web attack signatures, the raw HTTP log fields needed to build custom web attack logic live in the Web data model."
    ]
  },
  {
    id: "de-035",
    domain: "Detection Engineering",
    question: "During detection development in Splunk, an engineer needs to extract a username from a custom log field `raw_message` containing text like 'User=jdoe connected'. Which SPL command correctly extracts 'jdoe' into a new field named `extracted_user`?",
    options: [
      "| eval extracted_user=substr(raw_message, 6, 4)",
      "| rex field=raw_message \"User=(?<extracted_user>\\w+)\"",
      "| lookup users raw_message OUTPUT extracted_user",
      "| rename raw_message AS extracted_user"
    ],
    correct: 1,
    explanations: [
      "Incorrect. eval substr() extracts a fixed-position substring by character offset; it breaks for any username that differs in length or position from the hardcoded values — making it fragile and unfit for production detection use.",
      "Correct. The rex command applies a named capture group regex to extract values from a free-text field at search time. The pattern User=(?<extracted_user>\\w+) matches the literal 'User=' and captures the following word characters into extracted_user — reliably handling varying username lengths.",
      "Incorrect. The lookup command enriches events by matching an existing field against a lookup table to retrieve additional fields; it cannot extract a substring or pattern match from within a field's text value.",
      "Incorrect. rename changes the name of an existing field without modifying its value; it does not parse or extract content from within a field's string."
    ]
  },
  {
    id: "de-036",
    domain: "Detection Engineering",
    question: "A detection engineer is tuning a correlation search that generates too many false positives. Which statement best describes the core trade-off between lowering versus raising the alert threshold?",
    options: [
      "Lowering the threshold reduces both false positives and false negatives simultaneously",
      "Lowering the threshold increases false positives and reduces false negatives; raising it reduces false positives but increases false negatives",
      "Threshold settings affect only how frequently the search runs, not the quality of results",
      "Raising the threshold always improves detection quality and should always be preferred"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Lowering the threshold increases sensitivity, which captures more true positives but also lets in more false positives. It does not simultaneously reduce both error types.",
      "Correct. This describes the fundamental precision-recall trade-off in detection engineering. A lower threshold (higher sensitivity) catches more true attacks but also generates more false positives. A higher threshold (higher specificity) reduces false-positive noise but risks missing real attacks — increasing false negatives. Tuning requires balancing both in the context of the specific environment and use case.",
      "Incorrect. Threshold settings directly control the minimum result count or statistical value at which the alert fires, which has a direct impact on both false positive and false negative rates — not merely on run frequency.",
      "Incorrect. A high threshold is appropriate in noisy environments where false positive volume is the primary concern, but raising the threshold indefinitely will eventually cause real attacks to go undetected. There is no universally 'always preferred' direction; tuning depends on context."
    ]
  },

  /* ============================================================
     SECURITY PROCESSES AND PROGRAMS  (questions 13–18)
     ============================================================ */
  {
    id: "sp-013",
    domain: "Security Processes and Programs",
    question: "Which security architecture model is most effective at limiting lateral movement by requiring continuous verification of every user and device request regardless of network location?",
    options: [
      "Defense in Depth",
      "Zero Trust",
      "Lockheed Martin Cyber Kill Chain",
      "MITRE ATT&CK framework"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Defense in Depth is a layered security strategy using multiple controls across different tiers; while it adds obstacles for an attacker, it does not inherently prevent lateral movement once a credential is compromised within the trusted network.",
      "Correct. Zero Trust operates on the principle of 'never trust, always verify' — enforcing continuous authentication and authorization for every resource request regardless of whether the user is inside or outside the network perimeter. Microsegmentation and least-privilege access enforcement make lateral movement significantly harder even after initial compromise.",
      "Incorrect. The Cyber Kill Chain is a threat modeling framework that describes stages of an attack; it helps analysts understand adversary behavior but is not a security architecture model that prevents lateral movement.",
      "Incorrect. MITRE ATT&CK is a knowledge base of adversary tactics and techniques used for detection engineering and threat modeling; it is a reference framework, not a deployable security architecture."
    ]
  },
  {
    id: "sp-014",
    domain: "Security Processes and Programs",
    question: "A detection engineer wants to identify coverage gaps against specific MITRE ATT&CK techniques before writing new correlation searches, using a threat-defense-informed strategy. Which Splunk application is best suited for this guided use case development?",
    options: [
      "Enterprise Security Content Update (ESCU) app",
      "Splunk Security Essentials (SSE) app",
      "Splunk Add-on for MITRE ATT&CK Navigator",
      "Splunk Add-on for Microsoft Windows"
    ],
    correct: 1,
    explanations: [
      "Incorrect. ESCU delivers pre-built detection content; it does not provide an interactive interface for exploring which ATT&CK techniques are covered or for guided use case development workflows.",
      "Correct. The Splunk Security Essentials app provides an interactive experience for cross-referencing detections with the MITRE ATT&CK framework. It shows which techniques have coverage, identifies gaps, and guides engineers through analytic story development — making it the ideal tool for a threat-defense-informed detection strategy.",
      "Incorrect. While Splunk offers ATT&CK visualization, 'Splunk Add-on for MITRE ATT&CK Navigator' is not the designated app for guided use case development and coverage gap analysis; that role belongs to the Splunk Security Essentials app.",
      "Incorrect. The Splunk Add-on for Microsoft Windows is a technology add-on for collecting and normalizing Windows event logs; it does not provide ATT&CK coverage analysis or detection guidance."
    ]
  },
  {
    id: "sp-015",
    domain: "Security Processes and Programs",
    question: "A new security engineer wants to understand which data sources are available in their Splunk environment and how they map to CIM data models and security use cases before building new detections. Which Splunk component best provides this baseline inventory?",
    options: [
      "Enterprise Security Content Update (ESCU)",
      "Enterprise Security Data Library (ESDL)",
      "Splunk Security Essentials Analytic Stories",
      "Splunk CIM Add-on"
    ],
    correct: 1,
    explanations: [
      "Incorrect. ESCU provides pre-built detection content such as correlation searches and analytic stories; it does not inventory which data sources are present in the environment or assess their coverage readiness.",
      "Correct. The Enterprise Security Data Library (ESDL) catalogs the data sources available in a Splunk ES environment, showing how each maps to CIM data models and security use cases. It gives engineers a baseline of what data is available and highlights where detection gaps exist due to missing or incomplete data sources.",
      "Incorrect. SSE Analytic Stories provide detection guidance organized around threat scenarios; they do not specifically inventory or baseline the data sources currently ingested in the Splunk environment.",
      "Incorrect. The Splunk CIM Add-on provides data model schema definitions and normalization configuration; it does not provide a runtime inventory or coverage assessment of data sources that are actively sending data."
    ]
  },
  {
    id: "sp-016",
    domain: "Security Processes and Programs",
    question: "Which SOC metric measures the average elapsed time from when a security incident begins to when it is first detected by the security operations team?",
    options: [
      "Mean Time to Respond (MTTR)",
      "Mean Time to Detect (MTTD)",
      "Mean Time to Contain (MTTC)",
      "Mean Time Between Failures (MTBF)"
    ],
    correct: 1,
    explanations: [
      "Incorrect. MTTR (Mean Time to Respond) measures the elapsed time from the point of detection through the completion of response and remediation actions — it begins where MTTD ends.",
      "Correct. MTTD (Mean Time to Detect) is the average time between when a security incident starts and when the SOC first identifies it, typically through a SIEM alert or investigation finding. Reducing MTTD is a primary goal of detection engineering and data source coverage improvements.",
      "Incorrect. MTTC (Mean Time to Contain) measures how long it takes to isolate and stop the spread of an incident after it has been detected; it is a response-phase metric, not a detection speed metric.",
      "Incorrect. MTBF (Mean Time Between Failures) is an IT reliability metric measuring the average operating time between system failures; it is an infrastructure reliability KPI, not a security operations metric."
    ]
  },
  {
    id: "sp-017",
    domain: "Security Processes and Programs",
    question: "Which sequence correctly represents the phases of a formalized cyber threat intelligence (CTI) lifecycle?",
    options: [
      "Collect → Analyze → Process → Disseminate → Feedback",
      "Plan → Collect → Process → Analyze → Disseminate → Feedback",
      "Analyze → Collect → Disseminate → Plan → Feedback",
      "Disseminate → Collect → Process → Analyze → Plan"
    ],
    correct: 1,
    explanations: [
      "Incorrect. This sequence omits the initial Planning/Direction phase, which defines intelligence requirements before data collection begins. Without this phase there is no structured objective to guide what is collected or analyzed.",
      "Correct. The standard CTI lifecycle is: Plan/Direction (define requirements) → Collect (gather raw data from feeds and sensors) → Process (normalize, de-duplicate, enrich) → Analyze (derive actionable insights and context) → Disseminate (share finished intelligence with stakeholders) → Feedback (refine requirements for the next cycle).",
      "Incorrect. Analyzing data before collecting it is logically impossible; the planning phase must also precede collection to define what to gather and why.",
      "Incorrect. Disseminating intelligence before any collection, processing, or analysis has occurred inverts the entire lifecycle — no finished intelligence exists at the start of the cycle."
    ]
  },
  {
    id: "sp-018",
    domain: "Security Processes and Programs",
    question: "In Splunk Enterprise Security, how can a SOC formalize investigation runbook steps so that analysts are consistently prompted to follow a defined procedure when triaging a specific type of notable event?",
    options: [
      "By writing the runbook steps as SPL comments within the correlation search definition",
      "By configuring workflow actions or response templates that surface the investigation steps directly in the Incident Review interface",
      "By sending the runbook as an email attachment to the analyst when the notable event fires",
      "By storing the runbook as a saved search in the Splunk Knowledge Manager"
    ],
    correct: 1,
    explanations: [
      "Incorrect. SPL comments in a correlation search are only visible to engineers editing the search definition; they are not surfaced to analysts triaging notable events in Incident Review.",
      "Correct. Splunk ES supports configuring workflow actions and response templates that are displayed directly within the Incident Review interface when an analyst opens a notable event. These can include step-by-step investigation instructions, links to external knowledge bases, or embedded HTML guidance — ensuring consistent runbook adherence at triage time.",
      "Incorrect. Email delivery requires the analyst to leave the triage interface and check their mailbox separately, breaking workflow continuity and introducing the risk that the runbook is missed during high-volume incidents.",
      "Incorrect. Saved searches in Splunk are detection and reporting artifacts; they are not designed to present structured, contextual investigation guidance to analysts within the notable event triage workflow."
    ]
  },

  /* ============================================================
     AUTOMATION AND EFFICIENCY  (questions 13–18)
     ============================================================ */
  {
    id: "ae-013",
    domain: "Automation and Efficiency",
    question: "In a Splunk SOAR contextualization playbook, a suspicious URL must be submitted to a sandbox service API for detonation and analysis. Which HTTP method is used to transmit the URL in the request body to the sandbox endpoint?",
    options: [
      "GET",
      "POST",
      "PUT",
      "DELETE"
    ],
    correct: 1,
    explanations: [
      "Incorrect. GET requests transmit parameters in the URL query string; they are not suited for sending data payloads to a sandbox API and many sandbox APIs reject GET-based submissions because query strings are logged in plain text by proxies and servers.",
      "Correct. HTTP POST is used to submit data in the request body to a server-side resource. When submitting a URL or file to a sandbox for detonation, the SOAR playbook's App action uses POST so the submission payload can be included in the request body — supporting arbitrary payload sizes and keeping the data out of server access logs.",
      "Incorrect. PUT is used to update or replace an existing resource at a known URI; it is not the standard method for creating a new sandbox detonation submission.",
      "Incorrect. DELETE is used to remove an existing resource; it is entirely unrelated to submitting data for analysis."
    ]
  },
  {
    id: "ae-014",
    domain: "Automation and Efficiency",
    question: "A Splunk SOAR automation engineer has configured a new asset for a ticketing system and receives an HTTP 403 response code when the playbook attempts to use it. What is the most likely cause?",
    options: [
      "The asset's base URL is incorrect and the endpoint does not exist",
      "The asset's username or API token is incorrect and authentication is failing",
      "The asset credentials are valid but do not have sufficient permissions to perform the requested action",
      "The SOAR platform cannot reach the ticketing system due to a network routing issue"
    ],
    correct: 2,
    explanations: [
      "Incorrect. An incorrect URL or nonexistent endpoint would return an HTTP 404 (Not Found) response, not 403.",
      "Incorrect. Incorrect credentials or an invalid API token would return an HTTP 401 (Unauthorized) response, indicating that authentication itself failed — not 403.",
      "Correct. HTTP 403 (Forbidden) means the server successfully identified the requester (authentication passed) but the account does not have authorization to perform the specific operation. In SOAR asset configuration, this typically means the service account or API key is valid but lacks the required role or permissions for the API endpoint being called.",
      "Incorrect. A network routing or connectivity issue would typically result in a connection timeout or TCP-level error rather than an HTTP 403 response, because an HTTP response code requires the server to have received and processed the request."
    ]
  },
  {
    id: "ae-015",
    domain: "Automation and Efficiency",
    question: "When Splunk SOAR ingests notable events from Splunk Enterprise Security, which configuration ensures that Splunk data model field names (e.g., src_ip, dest_ip) are consistently mapped to SOAR's container and artifact fields?",
    options: [
      "Field aliases defined in props.conf on the Splunk search head",
      "CIM data model definitions in the Splunk Common Information Model add-on",
      "Global field mappings configured in the SOAR Splunk connector settings",
      "Custom SPL eval statements appended to each individual correlation search"
    ],
    correct: 2,
    explanations: [
      "Incorrect. props.conf field aliases normalize field names at Splunk search time for use within Splunk; they do not control how SOAR translates incoming event fields to its own internal container and artifact schema.",
      "Incorrect. The CIM add-on establishes field naming conventions within Splunk. SOAR has its own data model, so a separate mapping layer is needed to translate between the two schemas; the CIM add-on alone does not provide this.",
      "Correct. Global field mappings in the SOAR Splunk connector configuration define how Splunk event fields (following CIM naming conventions) are translated to SOAR artifact CEF fields and container metadata. This provides a centralized, consistent mapping that applies to all ES-to-SOAR event flows without requiring per-search customization.",
      "Incorrect. Appending eval statements to individual correlation searches can create new fields for specific searches but requires modifying every search separately and does not provide centralized, governance-controlled mapping across all notable-event-to-SOAR flows."
    ]
  },
  {
    id: "ae-016",
    domain: "Automation and Efficiency",
    question: "In Splunk ES Mission Control, how does the system determine which response template to automatically associate with a newly created finding?",
    options: [
      "The response template name is hard-coded in the correlation search's SPL via an eval statement",
      "Mission Control uses AI to select the most appropriate response template based on event content",
      "Response templates are mapped to specific incident types; the finding's incident type determines which template is applied",
      "An analyst must manually select a response template for every new finding before investigation can begin"
    ],
    correct: 2,
    explanations: [
      "Incorrect. Response templates are configured separately in Mission Control's incident type management interface; they are not embedded in correlation search SPL.",
      "Incorrect. While Mission Control incorporates AI-assisted capabilities for some features, response template assignment is deterministic — it is based on the configured incident type mapping, not AI inference.",
      "Correct. In Mission Control, response templates are associated with incident types. When a finding is created and assigned an incident type (e.g., 'Phishing', 'Ransomware', 'Insider Threat'), Mission Control automatically applies the pre-configured response template for that incident type, ensuring standardized and consistent investigation steps across the SOC.",
      "Incorrect. While analysts can override templates, the system is explicitly designed to automatically apply the appropriate template based on the incident type — this automatic assignment is a core value of Mission Control's structured response workflow."
    ]
  },
  {
    id: "ae-017",
    domain: "Automation and Efficiency",
    question: "A SOC's SOP requires that phishing email attachments detected in Splunk ES be submitted to Splunk Attack Analyzer for detonation. What is the most efficient implementation to automate this workflow at scale?",
    options: [
      "Configure a Splunk ES alert action to forward the attachment to a shared analyst mailbox for manual submission",
      "Create a Splunk SOAR playbook that automatically submits the attachment to Splunk Attack Analyzer and surfaces detonation results to the assigned analyst",
      "Enable all ESCU phishing detections and configure 24-hour throttling to reduce duplicate notables",
      "Use a scheduled SPL search to export attachment IOCs to a CSV file for weekly manual review"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Routing to a shared mailbox reintroduces manual steps and delays. During high-volume phishing campaigns, the shared mailbox creates a backlog and increases the risk of missed submissions.",
      "Correct. A SOAR playbook can automatically extract attachment indicators from the notable event container, submit them to the Splunk Attack Analyzer API, poll for detonation results, and present the disposition (benign/malicious/suspicious) to the analyst within the SOAR case — fully automating the SOP workflow and reducing analyst workload.",
      "Incorrect. Enabling ESCU phishing detections and tuning throttling improves detection coverage; it does not automate the Splunk Attack Analyzer submission workflow specified by the SOP.",
      "Incorrect. Weekly CSV review introduces unacceptable detection-to-analysis latency for phishing (which needs same-hour response) and re-adds the manual effort that the SOP automation is designed to eliminate."
    ]
  },
  {
    id: "ae-018",
    domain: "Automation and Efficiency",
    question: "In Splunk ES Risk-Based Alerting, what is the purpose of a 'risk factor' and how does it differ from a standard correlation search that adds risk?",
    options: [
      "A risk factor is a scheduled search that creates new risk events in the Risk Index independently of correlation search results",
      "A risk factor is a multiplier applied to a risk object's score based on its contextual characteristics (e.g., the user is a privileged account or the asset holds critical data), amplifying risk accumulation for high-value entities",
      "A risk factor is the minimum score threshold that must be exceeded before a risk incident rule fires",
      "A risk factor is the SOAR adaptive response action that converts aggregated risk events into SOAR containers"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Risk events in the Risk Index are generated by correlation searches that include the Risk Analysis adaptive response action; risk factors do not create events independently.",
      "Correct. A risk factor in RBA is a configurable multiplier (e.g., 1.5× or 2×) attached to a risk object based on its attributes — such as whether the user is a VIP executive or service account, or whether the asset contains PCI or PHI data. This causes risk to accumulate faster for higher-value targets, aligning RBA sensitivity with actual business impact rather than treating all entities equally.",
      "Incorrect. The minimum threshold is the trigger condition configured in the risk incident rule (e.g., aggregated score > 100); it is a separate concept from risk factor multipliers.",
      "Incorrect. Converting risk events to SOAR containers is handled by an Adaptive Response action configured on a risk incident rule, not by risk factors."
    ]
  },

  /* ============================================================
     DATA ENGINEERING  (questions 7–9)
     ============================================================ */
  {
    id: "deng-007",
    domain: "Data Engineering",
    question: "In Splunk's Common Information Model, what mechanism do technology add-ons use to associate raw events with a CIM data model (e.g., making firewall logs appear in the Network Traffic data model)?",
    options: [
      "The add-on writes events to a specially named CIM index during ingestion",
      "The add-on defines eventtypes in eventtypes.conf and assigns CIM-required tags in tags.conf",
      "The CIM add-on reads the technology add-on's lookup tables to find matching events",
      "A KV store collection maps the add-on's sourcetype names to data model names"
    ],
    correct: 1,
    explanations: [
      "Incorrect. CIM compliance does not require routing events to a special index; it is achieved through field normalization and event classification via eventtypes and tags, not index routing.",
      "Correct. Technology add-ons use eventtypes.conf to define which events belong to a category (e.g., by sourcetype and field values) and tags.conf to assign the CIM-required tags (e.g., tag=network tag=communicate) to those eventtypes. The CIM data models use these tag constraints in their root event definitions to determine which events populate each model.",
      "Incorrect. The CIM add-on provides data model schema definitions; it does not read lookup tables to find which events to include. That association is established through the eventtype-to-tag mapping in technology add-ons.",
      "Incorrect. KV store collections are used for lookup tables (threat intelligence IOCs, asset lists, etc.); they are not used to map sourcetypes or add-ons to CIM data models."
    ]
  },
  {
    id: "deng-008",
    domain: "Data Engineering",
    question: "A Splunk administrator must decide whether to extract a critical security field at index time or search time. Which statement correctly describes a key trade-off of index-time field extraction?",
    options: [
      "Index-time extraction is slower at search time but faster to configure than search-time extraction",
      "Index-time extraction permanently stores field values alongside raw events, improving search performance at the cost of increased storage",
      "Index-time extraction allows field names to be renamed after ingestion without reindexing",
      "Index-time extraction is only supported for JSON-formatted log sources"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Index-time extraction is faster at search time (the opposite of this option) because field values are pre-computed and stored. Configuration complexity is also greater, not lesser, because incorrect configurations cannot be corrected without reindexing.",
      "Correct. Index-time field extractions write the extracted field name and value into the index alongside the raw event. This means searches do not need to re-parse raw text at query time — improving performance. The trade-off is that the extracted values are stored redundantly with the raw data, increasing the index footprint.",
      "Incorrect. Index-time extractions are written permanently at ingest time and cannot be changed or renamed without reindexing historical data. Search-time extractions (via EXTRACT in props.conf) can be added, modified, or renamed without touching indexed data.",
      "Incorrect. Index-time field extractions can be configured for any structured or unstructured log format (syslog, CSV, JSON, custom delimited); availability is determined by the Splunk parsing pipeline, not by log structure."
    ]
  },
  {
    id: "deng-009",
    domain: "Data Engineering",
    question: "A new security data source produces logs where each line is a complete JSON object. What is the recommended Splunk props.conf setting to automatically extract all JSON key-value pairs as searchable fields without writing custom regex?",
    options: [
      "Configure a TRANSFORMS stanza in transforms.conf with a separate regex for each JSON key",
      "Set KV_MODE = json in props.conf for the sourcetype",
      "Enable data model acceleration for the JSON sourcetype",
      "Deploy a Heavy Forwarder to parse the JSON before forwarding to the indexer"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Writing individual TRANSFORMS regex stanzas for each JSON key is labor-intensive, brittle, and entirely unnecessary since Splunk has native JSON key-value extraction built into the parsing pipeline.",
      "Correct. Setting KV_MODE = json in props.conf instructs Splunk's search-time key-value extraction pipeline to parse each event as a JSON object and automatically extract all key-value pairs as searchable fields, with no custom regex required. For index-time extraction, INDEXED_EXTRACTIONS = json can also be used.",
      "Incorrect. Data model acceleration builds TSIDX summaries to speed up searches against pre-defined data model schemas; it does not extract field values from the raw event content.",
      "Incorrect. While a Heavy Forwarder can transform data before forwarding, routing JSON logs through an additional full Splunk instance purely for parsing introduces unnecessary infrastructure overhead when Splunk's native KV_MODE = json provides the same result with a single props.conf setting."
    ]
  },

  /* ============================================================
     AUDITING AND REPORTING  (questions 7–9)
     ============================================================ */
  {
    id: "ar-007",
    domain: "Auditing and Reporting",
    question: "Which Splunk Enterprise Security dashboard provides a high-level overview of the current security posture using Key Security Indicators (KSIs) — color-coded metrics across access, network, identity, and endpoint domains?",
    options: [
      "Incident Review dashboard",
      "Security Posture dashboard",
      "Risk Analysis dashboard",
      "Detection Studio Launchpad"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The Incident Review dashboard is the analyst triage interface showing individual notable events and their status; it does not aggregate or visualize security posture metrics across control domains.",
      "Correct. The Security Posture dashboard in Splunk ES presents Key Security Indicators (KSIs) as color-coded tiles across security control domains (access, endpoint, network, identity). It gives security managers and executives an at-a-glance summary of how well security controls are operating across the environment.",
      "Incorrect. The Risk Analysis dashboard displays risk score distributions, top risk objects, and contributing risk events; it is a tactical threat investigation tool, not a broad security posture summary.",
      "Incorrect. The Detection Studio Launchpad is an operational tool for detection engineers showing MITRE ATT&CK coverage and detection health; it is not intended as a security posture view for management or compliance audiences."
    ]
  },
  {
    id: "ar-008",
    domain: "Auditing and Reporting",
    question: "In Splunk, what is the fundamental difference between a scheduled alert and a scheduled report?",
    options: [
      "Scheduled alerts run more frequently; scheduled reports run less frequently by design",
      "A scheduled alert triggers configured actions only when its condition is met; a scheduled report always saves or distributes results regardless of content",
      "Scheduled reports can only be delivered as PDF attachments; scheduled alerts always create notable events",
      "Scheduled alerts use real-time search mode; scheduled reports always use historical time ranges"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Both scheduled alerts and reports can run at any frequency defined by a cron expression; run frequency is not an inherent architectural difference between the two types.",
      "Correct. A scheduled alert evaluates a condition (e.g., number of results > 0) after its search runs, and only fires its configured actions (email, webhook, notable event) when that condition is satisfied. A scheduled report always saves results and can distribute them (email, PDF, CSV) on schedule regardless of whether the content is 'interesting' — it does not have a conditional trigger.",
      "Incorrect. Both scheduled alerts and reports support multiple delivery formats, including inline email, CSV, and PDF. Alerts do not exclusively create notable events; they can also trigger email or custom alert actions.",
      "Incorrect. Both scheduled alerts and reports default to historical time range searches; real-time search mode is a separate option available to both types but is not a defining distinction between them."
    ]
  },
  {
    id: "ar-009",
    domain: "Auditing and Reporting",
    question: "A SOC manager wants to calculate Mean Time to Respond (MTTR) for notable events resolved in the past 30 days. Which Splunk indexes and approach would provide the necessary data?",
    options: [
      "Query the `risk` index and calculate the average urgency score across all risk objects",
      "Query the `notable` index for creation times and the `notable_updates` index for status-change timestamps, then calculate the elapsed time between creation and resolution",
      "Query the `threat_activity` index for events with a resolved status flag",
      "Use the Forwarder Audit dashboard's average indexing latency metric"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The risk index contains risk scoring events for the Risk Index framework; it does not track notable event creation timestamps or resolution activity needed for MTTR calculation.",
      "Correct. Notable events are stored in the notable index with their creation time. Analyst actions — including status changes to 'Resolved' — are recorded in the notable_updates index. By querying both and calculating the time difference between a notable's creation time and its resolution timestamp, a detection engineer can compute per-notable and average MTTR across any time window.",
      "Incorrect. The threat_activity index stores threat intelligence match events (IOC hits from the Threat Intelligence Framework); it does not contain notable event lifecycle data needed for MTTR measurement.",
      "Incorrect. The Forwarder Audit dashboard tracks data pipeline latency — the time between a forwarder collecting data and it appearing in the index. This is an infrastructure metric, not an incident response time metric."
    ]
  },

  /* ============================================================
     DETECTION ENGINEERING  (questions 37–48)
     ============================================================ */
  {
    id: "de-037",
    domain: "Detection Engineering",
    question: "A detection engineer wants to detect malicious process execution events such as PowerShell spawned by a Microsoft Office application. Which CIM data model and dataset provides the normalized fields for process name, parent process name, command-line arguments, and user?",
    options: [
      "Network Traffic data model — All_Traffic dataset",
      "Endpoint data model — Processes dataset",
      "Authentication data model — Default Authentication dataset",
      "Web data model — Web dataset"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The Network Traffic data model normalizes connection-level fields (src/dest IP, port, bytes, protocol); it does not contain process execution metadata such as parent process or command-line arguments.",
      "Correct. The CIM Endpoint data model's Processes dataset normalizes fields from EDR and Sysmon logs including process_name, parent_process_name, process_id, parent_process_id, process (command line), and user — making it the correct foundation for process-based detections like parent-child relationship anomalies.",
      "Incorrect. The Authentication data model covers login and credential events. While a user field exists, it does not provide process lineage, command-line arguments, or parent-child process relationships.",
      "Incorrect. The Web data model normalizes HTTP/proxy traffic; it contains no process execution fields."
    ]
  },
  {
    id: "de-038",
    domain: "Detection Engineering",
    question: "A detection engineer is building a search to identify Pass-the-Hash (PtH) authentication attacks against Windows systems. Which combination of Windows Security event fields is a primary indicator of PtH?",
    options: [
      "Event 4625 (failed logon) with a high count from a single source IP within a 5-minute window",
      "Event 4624 (successful logon) with Logon Type 3 (Network) using NTLM authentication originating from an unexpected internal host",
      "Event 4740 (account lockout) followed by Event 4624 from the same user within 10 minutes",
      "Event 4688 (process creation) showing lsass.exe launching cmd.exe"
    ],
    correct: 1,
    explanations: [
      "Incorrect. A high count of 4625 (failed logon) events indicates brute-force or password spray, not Pass-the-Hash. PtH typically produces successful authentications because the attacker uses a valid hash, not failed logons.",
      "Correct. Pass-the-Hash exploits the NTLM authentication protocol by replaying a captured password hash. This produces a successful Event 4624 with Logon Type 3 (Network logon) using NTLM — especially suspicious when the source host is a workstation that would not normally authenticate to the target using NTLM, or when no corresponding interactive logon exists.",
      "Incorrect. Account lockout followed by successful logon could indicate a user recovering from an inadvertent lockout; it is not a direct indicator of PtH, which produces successful authentications without prior failures.",
      "Incorrect. lsass.exe spawning cmd.exe is a potential indicator of credential dumping or LSASS exploitation — a different attack technique — not the network authentication pattern characteristic of PtH."
    ]
  },
  {
    id: "de-039",
    domain: "Detection Engineering",
    question: "In Splunk SPL, what is the key behavioral difference between the `search` command and the `where` command when filtering events in a detection pipeline?",
    options: [
      "`search` can only be used at the beginning of a pipeline; `where` can only be used at the end of a pipeline",
      "`search` filters using keyword matching and also searches raw event text (_raw); `where` evaluates a Boolean expression using eval-compatible functions against extracted field values only",
      "`search` is always faster than `where` for all filtering use cases in a correlation search",
      "`where` can match patterns in the raw _raw field; `search` can only filter on explicitly extracted fields"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Both `search` and `where` can appear anywhere in a pipeline after the initial search command; neither is restricted to a specific position.",
      "Correct. The `search` command accepts keyword terms and field=value expressions, and also scans the raw event text (_raw), making it useful for broad filtering. The `where` command evaluates a Boolean expression using eval functions (e.g., match(), like(), isnull()) applied strictly to extracted field values — it cannot search raw event text and requires fields to exist.",
      "Incorrect. Performance depends on the specific filter and data. `where` can actually be more efficient for complex field-based conditions because it uses eval's optimized expression engine, while `search` may scan raw text unnecessarily.",
      "Incorrect. This reverses the correct behavior. `search` is the command that can scan raw event text (_raw); `where` operates exclusively on extracted field values."
    ]
  },
  {
    id: "de-040",
    domain: "Detection Engineering",
    question: "An analyst suspects a compromised host is beaconing to a C2 server with highly regular periodic connections. Which SPL-based approach is most effective for identifying this pattern?",
    options: [
      "Alert on any connection where bytes_out exceeds a threshold to identify large data transfers",
      "Calculate the standard deviation of inter-connection time intervals per destination IP; a very low standard deviation indicates highly regular, machine-driven (beacon-like) traffic",
      "Match the destination IP against the ip_intel threat intelligence lookup for known malicious IPs",
      "Alert on any connection to a destination that has not been seen in the previous 30 days"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Large bytes_out values indicate potential exfiltration but not beaconing. C2 beacon traffic is often small (just keep-alive or command polling) and would not trigger a high-bytes threshold.",
      "Correct. Beaconing is characterized by machine-generated traffic at extremely regular intervals. Calculating the standard deviation of time gaps between consecutive connections from a host to a specific destination — using streamstats delta(_time) and then stats stdev — surfaces connections with near-zero variance in interval length, which is statistically improbable for human-initiated traffic.",
      "Incorrect. Matching against threat intelligence is useful for known-bad IOCs, but novel or newly stood-up C2 infrastructure will not appear in threat feeds. Beaconing detection is a behavioral approach that catches unknown C2 infrastructure.",
      "Incorrect. First-seen destination detection identifies new connections but will fire on every new external connection regardless of beaconing behavior, producing high false positive volumes without capturing the periodicity pattern."
    ]
  },
  {
    id: "de-041",
    domain: "Detection Engineering",
    question: "A detection engineer needs to build a time-series visualization showing the count of authentication failures per hour over the past 7 days to identify anomalous spikes. Which SPL command produces a correctly time-bucketed result for this purpose?",
    options: [
      "| stats count BY _time",
      "| timechart span=1h count WHERE action=failure",
      "| chart count OVER _time BY action",
      "| eventstats count AS hourly_count BY action"
    ],
    correct: 1,
    explanations: [
      "Incorrect. stats count BY _time groups by exact _time values (down to the second), producing thousands of single-event rows rather than hourly buckets. It does not aggregate into time intervals.",
      "Correct. timechart automatically buckets events into time intervals (span=1h creates one-hour buckets) and aggregates the count for each bucket. It produces a table with _time as the x-axis and the count as the y-axis, making it the correct command for time-series anomaly visualization.",
      "Incorrect. chart requires explicit OVER and BY clauses and does not automatically bucket _time into configurable spans; using it with a raw _time field produces per-second grouping like stats, not hourly buckets.",
      "Incorrect. eventstats computes aggregate statistics and appends them back to every original event without grouping into time buckets; it does not produce a time-series summary."
    ]
  },
  {
    id: "de-042",
    domain: "Detection Engineering",
    question: "In Splunk, which command computes a running (rolling) aggregate over a sliding time window and appends the result as a new field to each individual event, without collapsing the result set?",
    options: [
      "stats count BY user",
      "eventstats avg(count) AS avg_rate BY user",
      "streamstats time_window=1h count AS rolling_count BY user",
      "transaction user maxspan=1h"
    ],
    correct: 2,
    explanations: [
      "Incorrect. stats collapses all events into one row per group, discarding individual event records. It cannot compute a running windowed aggregate per event.",
      "Incorrect. eventstats computes a global aggregate across the full result set and appends it to every event, but it does not compute a sliding time-window aggregate — it calculates one value across all events, not a rolling value per time window.",
      "Correct. streamstats processes events in chronological order and computes running statistics within a configurable sliding time window (time_window=1h) scoped to a field (BY user), appending the current running value to each event. This preserves every individual event while adding a rolling count that detection logic can compare against thresholds.",
      "Incorrect. transaction groups consecutive events into a single merged event (a transaction); the individual events within the group are collapsed, making it unsuitable for per-event anomaly detection against a rolling count."
    ]
  },
  {
    id: "de-043",
    domain: "Detection Engineering",
    question: "An analyst suspects DNS tunneling is being used for data exfiltration. Which characteristic of DNS query data should a detection engineer focus on when building a correlation search for this technique?",
    options: [
      "DNS queries returning an NXDOMAIN (non-existent domain) response code",
      "DNS queries with unusually long subdomain labels or high-entropy random-looking domain names indicating encoded data",
      "DNS responses with TTL values greater than 3600 seconds indicating stale cache entries",
      "A single DNS query to an external resolver that bypasses the internal DNS server"
    ],
    correct: 1,
    explanations: [
      "Incorrect. NXDOMAIN responses indicate queries for domains that do not exist; while this can indicate DGA (domain generation algorithm) activity, it is not the defining indicator of DNS tunneling, which typically receives valid responses from attacker-controlled DNS servers.",
      "Correct. DNS tunneling encodes data (commands, exfiltrated content) into DNS query hostnames as subdomains. This produces unusually long subdomain labels (often exceeding 50 characters), high-entropy strings that look random or Base64-encoded, and an abnormally high query rate to the same domain — all detectable through statistical analysis of DNS query logs.",
      "Incorrect. High DNS TTL values affect how long resolvers cache responses; they are a configuration characteristic of the DNS server, not an indicator of tunneling activity in query patterns.",
      "Incorrect. A single query to an external resolver may indicate DNS over HTTPS circumvention or a misconfigured client, but by itself does not indicate tunneling. Tunneling is characterized by volume and encoding patterns, not a single bypass event."
    ]
  },
  {
    id: "de-044",
    domain: "Detection Engineering",
    question: "When using the SPL `lookup` command to enrich events with an asset table, what is the behavioral difference between `OUTPUT` and `OUTPUTNEW`?",
    options: [
      "`OUTPUT` appends new fields only when no existing field with that name exists; `OUTPUTNEW` always overwrites existing fields",
      "`OUTPUT` overwrites any existing field with the same name with the lookup value; `OUTPUTNEW` only populates a field if it does not already exist in the event",
      "`OUTPUT` requires a KV store lookup; `OUTPUTNEW` works only with CSV lookup files",
      "`OUTPUT` and `OUTPUTNEW` are functionally identical; the distinction was removed in Splunk 8.0"
    ],
    correct: 1,
    explanations: [
      "Incorrect. This describes the opposite of the actual behavior. OUTPUT overwrites; OUTPUTNEW preserves existing values.",
      "Correct. OUTPUT unconditionally writes the lookup field value to the event, overwriting any existing field with the same name. OUTPUTNEW is a non-destructive variant that only sets the field if the event does not already contain a field with that name — useful when you want to enrich events that are missing a field without replacing values that are already present.",
      "Incorrect. Both OUTPUT and OUTPUTNEW work with any lookup type — CSV files, KV store collections, and external lookup scripts. The lookup storage type does not determine which output clause is available.",
      "Incorrect. Both OUTPUT and OUTPUTNEW remain distinct and actively used SPL clauses in all current Splunk versions; their behavioral difference is a tested concept in Splunk certification exams."
    ]
  },
  {
    id: "de-045",
    domain: "Detection Engineering",
    question: "A detection engineer wants to identify credential dumping attacks targeting the Windows LSASS process. Which data source and event indicator is most directly relevant?",
    options: [
      "Windows Security Event 4624 with Logon Type 3 (Network) originating from the LSASS process",
      "Windows Sysmon Event ID 10 (ProcessAccess) where the target image is lsass.exe and GrantedAccess includes memory-read permissions",
      "Windows Security Event 4740 showing LSASS account lockout events",
      "Network Traffic logs showing the host making outbound connections on TCP/445 immediately after a logon"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Event 4624 records successful authentication logon events at the OS level; it records that LSASS processed a logon but does not record external processes attempting to read LSASS memory.",
      "Correct. Sysmon Event ID 10 (ProcessAccess) is generated when one process opens a handle to another process with specific access rights. Tools like Mimikatz request memory-read access (e.g., GrantedAccess 0x1010 or 0x1fffff) to lsass.exe to read credential material from memory — making this event the primary indicator for LSASS credential dumping.",
      "Incorrect. LSASS is not a user account and does not generate account lockout events (4740). Event 4740 records user account lockouts triggered by authentication failures.",
      "Incorrect. Outbound SMB connections (TCP/445) after a logon may indicate lateral movement using Pass-the-Hash, but they are a downstream effect — not the direct indicator of LSASS memory access that constitutes credential dumping."
    ]
  },
  {
    id: "de-046",
    domain: "Detection Engineering",
    question: "A detection engineer uses a subsearch to retrieve malicious IP addresses from a threat intelligence index and match them against live network events. What is a critical limitation of this approach that could silently reduce detection coverage?",
    options: [
      "Subsearches cannot reference indexed data; they can only read from KV store collections",
      "Subsearches are capped at 10,000 results by default; a threat intelligence list larger than this limit will be silently truncated, causing some IOCs to go unmatched",
      "Subsearches automatically clear the search head cache after each run, preventing data model acceleration from being used",
      "Subsearches always execute in real-time mode regardless of the parent search's scheduled time range"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Subsearches can query any Splunk index; they are not restricted to KV store collections. They are regular SPL searches that run before the main search and pass their results as a generated lookup.",
      "Correct. Splunk subsearches have a default maximum result limit of 10,000 rows (configurable via maxresults in limits.conf). If a threat intelligence list contains more than 10,000 indicators, the subsearch silently returns only the first 10,000 — with no warning to the analyst — leaving the remaining IOCs unmatched. This is a key reason why the `lookup` command against a KV store collection is preferred for large threat intel datasets.",
      "Incorrect. Subsearches do not clear the search head cache; they are standard searches that benefit from caching like any other query. Data model acceleration is unaffected by subsearch execution.",
      "Incorrect. Subsearches run within the same execution context as the parent search and honor the same scheduled time range configuration; they do not switch to real-time mode independently."
    ]
  },
  {
    id: "de-047",
    domain: "Detection Engineering",
    question: "An analyst is building an 'impossible travel' detection to flag users who authenticate from two geographically distant locations within a time window too short to physically travel between them. Which combination of Splunk capabilities is central to implementing this detection?",
    options: [
      "A stats count BY user to find users with more than one source IP in a session",
      "The iplocation command to geo-resolve source IPs, combined with stats to compare first and last authentication location per user within a time window",
      "A lookup against ip_intel to check if either source IP is a known VPN or Tor exit node",
      "A threshold alert on authentication failure counts per user per hour"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Counting source IPs per user identifies multi-location logins but cannot determine whether the distance between those locations is physically impossible without also resolving the geographic coordinates of each IP.",
      "Correct. The iplocation command enriches each authentication event with latitude, longitude, and country fields derived from the source IP. Combining this with stats or transaction to retrieve the first and last login location per user within a defined window, and then computing the geographic distance and comparing it against what is physically achievable in the elapsed time, implements the impossible travel logic.",
      "Incorrect. Checking against VPN/Tor lookups identifies suspicious proxy usage but does not detect impossible travel — a user could authenticate from two distant corporate locations without using a VPN.",
      "Incorrect. Authentication failure counts detect brute-force patterns; they do not address the geographic distance and time-window logic required for impossible travel detection."
    ]
  },
  {
    id: "de-048",
    domain: "Detection Engineering",
    question: "In Splunk ES, when a correlation search uses the `| collect` command to write results to a summary index, what is the primary security detection use case for this pattern?",
    options: [
      "Storing raw events in a secondary index for longer retention without affecting the main index size",
      "Pre-computing and caching expensive statistical baselines (e.g., daily user login counts) so that real-time correlation searches can compare live events against the stored baseline efficiently",
      "Replicating notable events to a backup Splunk deployment for disaster recovery",
      "Exporting correlation search results to a flat file for integration with third-party SIEM tools"
    ],
    correct: 1,
    explanations: [
      "Incorrect. While summary indexes can serve archival purposes, the security detection use case is specifically about baseline caching — not primary data retention management, which is an index lifecycle concern.",
      "Correct. Summary indexing with collect is used to store pre-computed aggregates (e.g., average login count per user per day over the past 30 days) in a small, fast summary index. Real-time detection searches then look up these baselines from the summary index rather than re-scanning weeks of raw events on every run, enabling efficient behavioral anomaly detection at scale.",
      "Incorrect. Summary indexing is not a replication or disaster recovery mechanism; Splunk's indexer clustering and SmartStore features handle high-availability and backup use cases.",
      "Incorrect. Summary indexes are native Splunk indexes, not flat files. Export to external systems would use the outputcsv command or a dedicated forwarding configuration — not collect into a summary index."
    ]
  },

  /* ============================================================
     SECURITY PROCESSES AND PROGRAMS  (questions 19–24)
     ============================================================ */
  {
    id: "sp-019",
    domain: "Security Processes and Programs",
    question: "Which sequence correctly represents the incident response lifecycle phases defined in NIST Special Publication 800-61?",
    options: [
      "Identify → Protect → Detect → Respond → Recover",
      "Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity",
      "Plan → Detect → Respond → Remediate → Report",
      "Triage → Escalate → Contain → Restore → Document"
    ],
    correct: 1,
    explanations: [
      "Incorrect. This sequence describes the five functions of the NIST Cybersecurity Framework (CSF), not the incident response lifecycle from SP 800-61. These are high-level organizational program functions, not IR operational phases.",
      "Correct. NIST SP 800-61 defines the incident response lifecycle as: Preparation (building capability before incidents occur) → Detection & Analysis (identifying and validating incidents) → Containment, Eradication & Recovery (stopping the incident and restoring systems) → Post-Incident Activity (lessons learned and process improvement).",
      "Incorrect. While this sequence describes a reasonable IR process intuitively, it is not the terminology used in NIST SP 800-61 and omits the Preparation phase, which NIST identifies as the most critical foundational element.",
      "Incorrect. This describes common SOC operational steps at a workflow level but does not correspond to the formal NIST SP 800-61 IR lifecycle phases."
    ]
  },
  {
    id: "sp-020",
    domain: "Security Processes and Programs",
    question: "In a three-tier SOC model, which description best characterizes the primary responsibility of a Tier-3 analyst?",
    options: [
      "Monitoring the SIEM dashboard and triaging newly generated alerts using standard runbooks",
      "Investigating alerts escalated from Tier-1 that require more context and deeper analysis beyond standard runbooks",
      "Conducting proactive threat hunting, performing advanced forensic and malware analysis, and developing new detection capabilities",
      "Managing Splunk infrastructure, data pipeline health, and user access provisioning"
    ],
    correct: 2,
    explanations: [
      "Incorrect. Monitoring the SIEM dashboard and performing initial triage using standard runbooks is the primary responsibility of Tier-1 analysts — the first point of contact for incoming alerts.",
      "Incorrect. Handling escalations that require deeper contextual investigation beyond runbooks describes Tier-2 analyst work, which bridges the gap between routine triage and advanced threat analysis.",
      "Correct. Tier-3 analysts are the most experienced members of the SOC. Their work focuses on proactive threat hunting (finding unknown threats before alerts fire), advanced forensic and malware analysis, reverse engineering, and contributing back to the team by developing new detection logic, playbooks, and improving the overall detection capability.",
      "Incorrect. Managing Splunk infrastructure, data pipelines, and user provisioning is typically an engineering or platform operations function — not a SOC analyst tier responsibility, regardless of tier level."
    ]
  },
  {
    id: "sp-021",
    domain: "Security Processes and Programs",
    question: "In Splunk ES, the urgency of a notable event is calculated from two inputs. Which field from the Asset and Identity framework combines with the correlation search's configured severity to determine urgency?",
    options: [
      "The risk_score accumulated in the Risk Index for the associated risk object",
      "The priority field assigned to the affected asset or identity in the Asset and Identity lookup",
      "The ESCU content confidence score assigned to the detection",
      "The throttle period configured on the correlation search"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The risk_score in the Risk Index is an accumulation of behavioral risk events used by RBA; it is not an input to the urgency calculation on individual notable events generated by standard correlation searches.",
      "Correct. The urgency field on a notable event is computed by combining the correlation search's configured severity level (informational, low, medium, high, critical) with the priority of the matched asset or identity from the Asset and Identity framework (unknown, low, medium, high, critical). A high-severity detection on a critical-priority asset produces a 'critical' urgency, ensuring the most important systems receive the most immediate attention.",
      "Incorrect. ESCU content confidence scores indicate how reliable a detection is as a true-positive indicator; they inform tuning decisions but are not a direct input to the urgency calculation formula.",
      "Incorrect. The throttle period controls duplicate notable suppression; it has no role in computing the urgency level of a notable event."
    ]
  },
  {
    id: "sp-022",
    domain: "Security Processes and Programs",
    question: "An analyst reviewing notable events in Splunk ES sees multiple detections mapped to the MITRE ATT&CK 'Discovery' tactic (TA0007). What type of adversary activity does this tactic represent?",
    options: [
      "Techniques used to gain initial access to a network, such as phishing or exploiting a public-facing application",
      "Techniques used to enumerate internal systems, accounts, services, network topology, and installed software after gaining a foothold",
      "Techniques used to exfiltrate sensitive data out of the compromised environment",
      "Techniques used to achieve and maintain a persistent foothold across system reboots and credential changes"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Gaining initial access is covered by the MITRE ATT&CK 'Initial Access' tactic (TA0001), which describes the first techniques used to enter a network. Discovery occurs after a foothold has already been established.",
      "Correct. The Discovery tactic (TA0007) covers techniques adversaries use after gaining access to learn about the internal environment — such as enumerating user accounts, system information, network shares, active directory objects, and running processes. This reconnaissance of the internal network helps attackers plan further actions like lateral movement and privilege escalation.",
      "Incorrect. Data exfiltration is covered by the 'Exfiltration' tactic (TA0010), which describes techniques for stealing data after it has been collected. Discovery precedes collection and exfiltration in the attack chain.",
      "Incorrect. Maintaining persistence across restarts and credential changes is covered by the 'Persistence' tactic (TA0003). Discovery is about learning about the environment, not about ensuring continued access."
    ]
  },
  {
    id: "sp-023",
    domain: "Security Processes and Programs",
    question: "Which standard format and transport protocol pair are most commonly used to exchange structured cyber threat intelligence (CTI) between organizations in a machine-readable, automated way?",
    options: [
      "CSV files transported over HTTPS",
      "STIX (Structured Threat Information Expression) transported over TAXII (Trusted Automated Exchange of Intelligence Information)",
      "JSON payloads delivered over FTP",
      "YARA rules shared via email"
    ],
    correct: 1,
    explanations: [
      "Incorrect. CSV files over HTTPS are a simple, human-readable format used for basic IOC sharing but lack the rich context, relationship modeling, and automated processing capabilities of STIX. CSV has no standard schema for expressing attack patterns, campaigns, or threat actor TTPs.",
      "Correct. STIX is the standardized schema for expressing CTI objects (indicators, malware, threat actors, attack patterns, etc.) in a structured, machine-readable format. TAXII is the transport protocol that defines how STIX bundles are served and consumed via a client-server model. Together they form the industry-standard automated threat intelligence sharing framework supported by Splunk ES's TAXII feed ingestion.",
      "Incorrect. FTP is an insecure, non-standard, and non-automated transport for CTI. It provides no schema for structured intelligence objects and is not used in modern threat intelligence sharing platforms.",
      "Incorrect. YARA rules are used for malware pattern matching in file analysis; they are a detection artifact, not a structured threat intelligence format. They are shared informally and do not carry the rich context (actor attribution, campaign information, kill chain mapping) that STIX provides."
    ]
  },
  {
    id: "sp-024",
    domain: "Security Processes and Programs",
    question: "In incident response terminology, what does 'dwell time' measure?",
    options: [
      "The time it takes for a Splunk correlation search to return results after execution",
      "The elapsed time between when an attacker first gains access to an environment and when the intrusion is discovered by the security team",
      "The duration a notable event remains in 'In Progress' status in Incident Review before being resolved",
      "The time required to restore a compromised system to full operation after eradication"
    ],
    correct: 1,
    explanations: [
      "Incorrect. Search execution latency is a Splunk performance metric, not an incident response concept. Dwell time refers to attacker presence in an environment, not system response times.",
      "Correct. Dwell time (also called 'breakout time' in some frameworks) measures how long an attacker remains undetected inside a compromised environment — from the moment of initial access to the moment of discovery. Reducing dwell time is a primary SOC objective because shorter dwell time limits the attacker's opportunity for lateral movement, data staging, and exfiltration.",
      "Incorrect. The time a notable event spends in a specific status is a SOC workflow metric related to MTTR (Mean Time to Respond); it is a process efficiency measurement, not a measurement of attacker presence duration.",
      "Incorrect. Recovery time after remediation is a component of MTTR or Recovery Time Objective (RTO); it measures the restoration phase after an incident has been detected and contained, not the period of undetected attacker presence."
    ]
  },

  /* ============================================================
     AUTOMATION AND EFFICIENCY  (questions 19–24)
     ============================================================ */
  {
    id: "ae-019",
    domain: "Automation and Efficiency",
    question: "In Splunk SOAR, what is the purpose of a 'workbook' in the context of incident response?",
    options: [
      "A visual drag-and-drop editor for designing automated playbook logic flows",
      "A structured set of tasks and phases that guide analysts through a defined investigation or response procedure with trackable completion status",
      "A saved SPL search template that playbooks use to query Splunk index data",
      "A configuration file that maps incoming SOAR containers to Splunk ES notable event fields"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The visual drag-and-drop editor for designing automated playbook logic is the SOAR Playbook Editor (Visual Playbook Editor), not a workbook.",
      "Correct. A SOAR workbook is a structured, human-facing incident response template containing tasks organized into phases (e.g., Triage, Containment, Eradication, Recovery). Each task can be assigned to an analyst, marked complete, and tracked — providing a governed, auditable checklist that runs alongside automated playbooks to ensure all manual investigation steps are completed.",
      "Incorrect. SPL search templates for playbooks are configured within the Splunk App action blocks inside a playbook; they are not workbooks.",
      "Incorrect. Container-to-notable field mapping is handled by the global field mappings and label-based routing configuration in the SOAR Splunk connector; this is not a workbook function."
    ]
  },
  {
    id: "ae-020",
    domain: "Automation and Efficiency",
    question: "In Splunk SOAR, an automation engineer marks a newly developed playbook as 'inactive'. What is the effect of this setting?",
    options: [
      "The playbook runs in a sandboxed debug mode, logging all actions without executing them on real systems",
      "The playbook is prevented from running automatically via label-based triggers but can still be run manually on-demand against specific containers",
      "The playbook is soft-deleted and permanently removed from the environment after 30 days",
      "The playbook continues to run automatically but skips any action blocks that would modify external systems"
    ],
    correct: 1,
    explanations: [
      "Incorrect. SOAR has a separate 'Debug' execution mode (run in debug) that allows playbooks to be tested with simulated actions; this is distinct from the active/inactive status toggle.",
      "Correct. Setting a playbook to 'inactive' disables automatic triggering — the playbook will not run when a new container matches its label filters. However, an analyst can still manually invoke the inactive playbook on-demand from a specific container's event details page, which is useful during testing and review before the playbook is promoted to active production use.",
      "Incorrect. SOAR does not automatically delete inactive playbooks on a timer. Inactive playbooks remain in the environment indefinitely until explicitly deleted by an administrator.",
      "Incorrect. There is no selective action-skipping mode in SOAR based on active/inactive status; the inactive flag controls whether the playbook runs at all via automatic triggers, not which blocks within it execute."
    ]
  },
  {
    id: "ae-021",
    domain: "Automation and Efficiency",
    question: "In Splunk SOAR's data model, what is the relationship between a 'container' and an 'artifact'?",
    options: [
      "A container is a single event field value; an artifact is the parent record that groups multiple field containers",
      "A container is the top-level incident or case record; artifacts are the individual data objects (IP addresses, file hashes, URLs, email addresses) associated with that case",
      "A container holds playbook execution logs; artifacts hold the original raw event data from the SIEM",
      "Container and artifact are interchangeable terms; they refer to the same SOAR data structure"
    ],
    correct: 1,
    explanations: [
      "Incorrect. This reverses the correct hierarchy. A container is the parent record (the case/incident); it is not a single field value.",
      "Correct. In SOAR's data model, a container is the top-level record that represents a security incident or event (analogous to a ticket in a ITSM system). Artifacts are the individual observable data objects — such as source IP addresses, destination IPs, file hashes, URLs, email headers, or usernames — that are associated with the container and used as inputs to playbook App actions.",
      "Incorrect. Playbook execution logs are stored in the SOAR audit trail and task output, not in containers. Containers hold the case data; their artifacts are observables, not log data.",
      "Incorrect. Container and artifact are distinct concepts with a clear parent-child relationship in SOAR's data model; treating them as interchangeable would break playbook data path references and artifact iteration logic."
    ]
  },
  {
    id: "ae-022",
    domain: "Automation and Efficiency",
    question: "A Splunk ES Adaptive Response action is configured with 'Run on each result' instead of 'Run once'. How does this change the behavior when a correlation search returns multiple matching events?",
    options: [
      "'Run on each result' invokes the action once per unique field value in the results; 'Run once' invokes the action for only the first unique field value found",
      "'Run on each result' invokes the action once per row returned by the correlation search; 'Run once' invokes the action a single time regardless of how many results were returned",
      "'Run on each result' requires a connected Splunk SOAR instance; 'Run once' can execute built-in ES actions without SOAR",
      "'Run on each result' is only available for the Risk Analysis action; 'Run once' is the only mode for the Create Notable Event action"
    ],
    correct: 1,
    explanations: [
      "Incorrect. 'Run on each result' invokes the action for every row in the result set, not just per unique field value. Deduplication logic would need to be implemented separately if only unique values are desired.",
      "Correct. 'Run on each result' triggers one action invocation per result row in the correlation search output — useful when you need to create a separate ticket or send a separate notification per affected entity. 'Run once' triggers a single action invocation regardless of result count, useful when the action should summarize all findings (e.g., one email listing all matched events).",
      "Incorrect. Both 'Run on each result' and 'Run once' can execute any configured Adaptive Response action — including built-in ES actions and SOAR-based actions. The execution mode is independent of whether SOAR is connected.",
      "Incorrect. Both execution modes are available for all Adaptive Response action types, including Risk Analysis, Create Notable Event, and third-party actions. There is no restriction binding a mode to a specific action type."
    ]
  },
  {
    id: "ae-023",
    domain: "Automation and Efficiency",
    question: "A SOAR playbook receives a container with five IP address artifacts. The engineer wants a threat intelligence App action to run independently for each IP. Which configuration approach causes SOAR to automatically invoke the action once per artifact?",
    options: [
      "Write a Python custom function that loops over the artifact list and calls the action five times sequentially",
      "Configure the App action's input data path to reference the artifact CEF field (e.g., artifact:*.cef.destinationAddress), which causes SOAR to fan out and invoke the action once per matching artifact value",
      "Create five separate parallel playbooks, one for each IP artifact, and trigger them from a parent playbook",
      "Use a Format block to concatenate all five IPs into a comma-separated string for a single bulk API request"
    ],
    correct: 1,
    explanations: [
      "Incorrect. While a custom function can achieve iteration, it adds unnecessary complexity and is not the idiomatic SOAR approach. The built-in data path fan-out mechanism is designed precisely for this purpose.",
      "Correct. When an App action's input data path references a wildcard artifact field (using the * glob, e.g., artifact:*.cef.destinationAddress), SOAR automatically fans out the action — creating one invocation per matching artifact value. This is SOAR's native per-artifact iteration pattern and is the recommended, most concise approach.",
      "Incorrect. Creating five separate child playbooks for five IPs is a high-overhead pattern that does not scale with dynamic artifact counts and is not the intended mechanism for per-artifact action invocation.",
      "Incorrect. Concatenating IPs into a single string for a bulk request only works if the threat intelligence API supports batch lookups; it does not leverage SOAR's native per-artifact fan-out and requires additional parsing logic to split the API response back into per-IP results."
    ]
  },
  {
    id: "ae-024",
    domain: "Automation and Efficiency",
    question: "A SOC team closes a SOAR case after resolving an incident. Which integration capability allows this status change to be reflected back in the corresponding notable event in Splunk ES Incident Review automatically?",
    options: [
      "The Splunk CIM add-on automatically syncs case status between SOAR and ES via the common data model",
      "The bidirectional sync feature of the Splunk ES and SOAR integration, where SOAR updates the notable event's status and owner fields via the Splunk REST API when the container is resolved",
      "The analyst must manually update the notable event status in ES Incident Review as a separate step",
      "Incident Review notable event statuses are read-only system fields and cannot be updated by any external system"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The CIM add-on provides data model definitions and field normalization within Splunk; it does not perform real-time bidirectional case status synchronization between SOAR and ES.",
      "Correct. The Splunk ES and SOAR integration supports bidirectional synchronization. When a SOAR container status is updated (e.g., closed or resolved), the SOAR Splunk app can write back to the Splunk ES notable event via the REST API — updating the notable's status field and optionally its owner and comment — keeping both systems in sync without requiring manual analyst intervention.",
      "Incorrect. While manual updating is the fallback if the integration is not configured, the integration is specifically designed to automate this synchronization so analysts do not have to maintain both systems separately.",
      "Incorrect. Notable event status, owner, urgency, and comment fields in Incident Review are fully writable — both through the UI and via the Splunk REST API. They are not read-only system fields."
    ]
  },

  /* ============================================================
     DATA ENGINEERING  (questions 10–12)
     ============================================================ */
  {
    id: "deng-010",
    domain: "Data Engineering",
    question: "In Splunk's indexer storage architecture, what is the correct lifecycle order through which an index bucket transitions?",
    options: [
      "Cold → Warm → Hot → Frozen",
      "Hot → Warm → Cold → Frozen",
      "Hot → Cold → Warm → Archived",
      "Warm → Hot → Frozen → Cold"
    ],
    correct: 1,
    explanations: [
      "Incorrect. This is the reverse of the correct order. Buckets begin as Hot (actively written), not Cold.",
      "Correct. Splunk index buckets follow the lifecycle: Hot (actively receiving new events, stored on fastest storage) → Warm (no longer receiving writes but still searchable, on fast storage) → Cold (older data, moved to slower/cheaper storage, still searchable) → Frozen (oldest data, either deleted or archived to external storage based on configuration). This tiered lifecycle enables cost-effective storage management aligned to data access frequency.",
      "Incorrect. There is no direct Hot → Cold transition without first going through Warm, and the lifecycle does not include a separate 'Archived' stage within Splunk's bucket management.",
      "Incorrect. Buckets begin as Hot (not Warm) when they are first created and actively written to; there is no backward transition from Frozen or Cold back to Hot."
    ]
  },
  {
    id: "deng-011",
    domain: "Data Engineering",
    question: "In Splunk, three default metadata fields are assigned to every indexed event. Which statement correctly distinguishes `host`, `source`, and `sourcetype`?",
    options: [
      "`source` identifies the device that sent the data; `host` identifies the specific file or port input; `sourcetype` describes the Splunk index destination",
      "`host` identifies the system that generated or forwarded the event; `source` is the specific file path, network port, or input from which the data came; `sourcetype` describes the data format and governs parsing rules",
      "`sourcetype` identifies the Splunk index the event was written to; `host` is the analyst who ran the originating search; `source` contains the raw event content",
      "All three fields are interchangeable within SPL searches and can substitute for each other in any filter expression"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The roles are incorrect in this option. source refers to the file/port input, not the device; host identifies the device/system; sourcetype describes data format, not the destination index.",
      "Correct. host is the hostname of the system that generated the event (or the forwarder that sent it). source is the specific input from which the data came — such as a file path (/var/log/auth.log), a network port (UDP:514), or a scripted input name. sourcetype categorizes the data format, telling Splunk's parsing pipeline which rules (props.conf) to apply for timestamp extraction, line breaking, and field extraction.",
      "Incorrect. The index an event is written to is tracked internally by Splunk as the `index` field, not sourcetype. The host field is the originating system hostname, not the analyst's identity.",
      "Incorrect. host, source, and sourcetype serve fundamentally different roles and are not interchangeable. Using them interchangeably in SPL would produce incorrect filter results."
    ]
  },
  {
    id: "deng-012",
    domain: "Data Engineering",
    question: "A security team is onboarding a new application that outputs structured syslog messages with custom key=value pairs that are not in any existing Splunk add-on. Which configuration file and stanza type should be used to define automatic search-time field extractions for these custom key-value pairs?",
    options: [
      "outputs.conf — tcpout stanza",
      "props.conf — KV_MODE or EXTRACT stanza for the sourcetype",
      "transforms.conf — LOOKUP stanza",
      "inputs.conf — monitor stanza with a fields override"
    ],
    correct: 1,
    explanations: [
      "Incorrect. outputs.conf configures where Splunk forwarders send data (indexer destinations, HEC endpoints); it has no role in field extraction or parsing.",
      "Correct. props.conf governs all sourcetype-level parsing behavior. For key=value structured syslog, setting KV_MODE = auto or KV_MODE = multi in props.conf for the sourcetype instructs Splunk to automatically extract key=value pairs at search time. For more specific patterns, an EXTRACT stanza with a named capture group regex can be defined for precise field extraction without requiring a full transforms.conf entry.",
      "Incorrect. LOOKUP stanzas in transforms.conf define lookup table definitions (CSV or KV store references) for field enrichment; they do not extract field values from raw event text.",
      "Incorrect. inputs.conf monitor stanzas configure which files or directories to monitor and can set basic metadata (host, source, sourcetype, index) but cannot define field extraction logic for the event content."
    ]
  },

  /* ============================================================
     AUDITING AND REPORTING  (questions 10–12)
     ============================================================ */
  {
    id: "ar-010",
    domain: "Auditing and Reporting",
    question: "A SOC manager wants to identify notable events that have been in 'In Progress' status for more than 4 hours without a status update, indicating SLA breaches. Which approach in Splunk ES best surfaces these events?",
    options: [
      "Filter the Forwarder Audit dashboard by high-urgency events older than 4 hours",
      "Create a scheduled SPL search against the `notable` and `notable_updates` indexes to find events whose last status change timestamp exceeds 4 hours ago",
      "Enable the built-in 'SLA Breach' detection in the Detection Studio Launchpad",
      "Filter the Risk Analysis dashboard for risk objects with scores that have not changed in 4 hours"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The Forwarder Audit dashboard reports on data pipeline health and forwarder connectivity; it contains no notable event lifecycle or SLA tracking data.",
      "Correct. Notable event creation and status changes are tracked in the notable and notable_updates indexes respectively. A scheduled SPL search can join these to calculate the elapsed time since each event's last status update, filter for events in 'In Progress' status where that elapsed time exceeds the 4-hour SLA threshold, and optionally trigger an alert or report to the manager.",
      "Incorrect. Detection Studio Launchpad is an operational tool for detection engineers showing MITRE ATT&CK coverage and detection health; it does not contain SLA tracking functionality for analyst workflow compliance.",
      "Incorrect. Risk Analysis tracks behavioral risk score changes for risk objects; it does not monitor the lifecycle of individual notable events or analyst response timelines."
    ]
  },
  {
    id: "ar-011",
    domain: "Auditing and Reporting",
    question: "A compliance officer needs a daily automated report of all critical and high urgency notable events from the previous 24 hours, delivered to a distribution list each morning. Which Splunk feature best fulfills this requirement?",
    options: [
      "A real-time alert configured to email the compliance officer each time a critical notable event fires",
      "A scheduled report configured to run daily, querying the previous 24 hours, with results delivered as a PDF or CSV email attachment to the distribution list",
      "A Glass Table dashboard published to a public URL that the compliance team bookmarks",
      "A Splunk SOAR playbook configured to email a notable event summary every 24 hours"
    ],
    correct: 1,
    explanations: [
      "Incorrect. A real-time alert sends individual emails per event as they fire throughout the day — potentially hundreds of emails — rather than a consolidated daily digest. This approach does not meet the requirement for a single morning delivery.",
      "Correct. A scheduled report (cron-scheduled to run each morning) runs its search against the previous 24-hour window, compiles all matching critical and high urgency notable events into a result set, and delivers the output as a formatted PDF or CSV email attachment to a distribution list — exactly matching the compliance requirement.",
      "Incorrect. A Glass Table dashboard provides a visual real-time posture view but requires the compliance officer to actively navigate to it; it does not push a report automatically and does not produce an auditable document suitable for compliance records.",
      "Incorrect. While a SOAR playbook could be constructed to perform this function, it would require custom development and additional infrastructure. The native Splunk scheduled report feature achieves this requirement directly with no custom code."
    ]
  },
  {
    id: "ar-012",
    domain: "Auditing and Reporting",
    question: "A Splunk administrator suspects analysts are running poorly optimized ad-hoc searches that are degrading search head performance. Which built-in Splunk capability allows the administrator to audit search activity and identify resource-intensive queries across all users?",
    options: [
      "The Forwarder Audit dashboard filtered by search head hostname",
      "The _audit index combined with the Search Activity dashboard in the Splunk Monitoring Console",
      "The Detection Studio Launchpad filtered by analyst username",
      "The Suppression Audit dashboard sorted by most recently modified rules"
    ],
    correct: 1,
    explanations: [
      "Incorrect. The Forwarder Audit dashboard tracks data pipeline health and forwarder connectivity; it does not record search execution activity, query run times, or per-user search history.",
      "Correct. Splunk writes audit events for every search execution to the internal _audit index, including the running user, search string, execution time, and result counts. The Search Activity dashboard in the Splunk Monitoring Console (or the _audit index queried directly) surfaces per-user search volume, slowest searches, and resource consumption — enabling administrators to identify and address poorly optimized queries.",
      "Incorrect. Detection Studio Launchpad is scoped to correlation search and detection content management; it does not provide visibility into ad-hoc search activity by individual users.",
      "Incorrect. The Suppression Audit dashboard tracks notable event suppression rule activity; it has no relevance to search execution performance or user search audit trails."
    ]
  }

];
