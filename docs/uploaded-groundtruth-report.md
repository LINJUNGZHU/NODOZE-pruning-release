# Uploaded DARPA archive audit

Archive SHA-256: `a967a224c6f02a6045892137e11919eea5fb3bdc8fa2e711ce086fd39b6fa16a`.

The ZIP provides static positive entity UUID labels and attributes, with an Orthrus-local index_id. It provides no event labels, timestamps, malicious paths, or verified negative labels. All UUID comparisons ignore case; index_id is never used for database matching.

| Dataset / CSV | Rows | DB matched | Method | Retained labeled nodes | Derived events retained |
|---|---:|---:|---|---:|---:|
| E3-CADETS/node_Nginx_Backdoor_06.csv | 8 | 8/8 | saved_pruning@0.2 | 8/8 | 264/268 |
| E3-CADETS/node_Nginx_Backdoor_06.csv | 8 | 8/8 | rasp_d0@0.2 | 8/8 | 268/268 |
| E3-CADETS/node_Nginx_Backdoor_12.csv | 43 | 43/43 | saved_pruning@0.2 | 35/43 | 415/5000 |
| E3-CADETS/node_Nginx_Backdoor_12.csv | 43 | 43/43 | rasp_d0@0.2 | 35/43 | 4958/5000 |
| E3-CADETS/node_Nginx_Backdoor_13.csv | 24 | 24/24 | saved_pruning@0.2 | 14/24 | 376/497 |
| E3-CADETS/node_Nginx_Backdoor_13.csv | 24 | 24/24 | rasp_d0@0.2 | 14/24 | 419/497 |
| E3-CLEARSCOPE/node_clearscope_e3_firefox_0411.csv | 41 | unavailable | unavailable | N/A | N/A |
| E3-THEIA/node_Browser_Extension_Drakon_Dropper.csv | 61 | 61/61 | saved_pruning@0.2 | 60/61 | 664/870 |
| E3-THEIA/node_Browser_Extension_Drakon_Dropper.csv | 61 | 61/61 | rasp_d0@0.2 | 61/61 | 870/870 |
| E3-THEIA/node_Firefox_Backdoor_Drakon_In_Memory.csv | 58 | 58/58 | unavailable | N/A | N/A |
| E5-CADETS/node_Nginx_Drakon_APT.csv | 19 | unavailable | unavailable | N/A | N/A |
| E5-CADETS/node_Nginx_Drakon_APT_17.csv | 107 | unavailable | unavailable | N/A | N/A |
| E5-CLEARSCOPE/node_clearscope_e5_appstarter_0515.csv | 26 | unavailable | unavailable | N/A | N/A |
| E5-CLEARSCOPE/node_clearscope_e5_lockwatch_0517.csv | 17 | unavailable | unavailable | N/A | N/A |
| E5-CLEARSCOPE/node_clearscope_e5_tester_0517.csv | 8 | unavailable | unavailable | N/A | N/A |
| E5-THEIA/node_THEIA_1_Firefox_Drakon_APT_BinFmt_Elevate_Inject.csv | 70 | unavailable | unavailable | N/A | N/A |

These are retrospective graph-retention measurements, not classifier accuracy. Static node membership across all entity types does not establish a malicious causal path. Derived events merely connect two labeled entities; CADETS uses saved annotation windows, whereas THEIA uses all events in the explicitly selected database. These denominators are not interchangeable.

The RASP-D primary setting was selected post hoc using development-case recall. Existing POIs/candidates may use analyst or ground-truth-derived information. The uploaded labels are byte-identical to the existing labels wherever reported, so this is not an independent held-out test.

Absent datasets and incomplete runs have N/A retention, never fabricated zero or perfect results. No OPTC or TRACE CSV is present. CLEARSCOPE and E5 lack matching local databases in this input configuration. SQLite connections are read-only. Large database identity uses size/mtime and matched-content digests; the archive, every CSV, annotation, comparison, and saved ledger has a full SHA-256.
