# Usage

Once you've connected to SO-CRATES in your browser, here are some of the things you can do. Start with the tour below, then dig into the details:

- [Analyzing Files](analyzing-files.md) - uploading, loading from a URL, ZIPs, and reanalyzing
- [Exploring Results](exploring-results.md) - what each tab shows for PCAP, log, and binary analyses, including DNS Heuristics
- [Filtering & Drill-Down](filtering-and-drilldown.md) - the pivot menu, AI summaries, playbooks, notes, and stream analysis
- [Keyboard & Menus](keyboard-and-menus.md) - keyboard navigation, the command palette, and the gear menu

## Screenshot Tour

When you first connect to SO-CRATES, a welcome window will appear with an overview of SO-CRATES:

![Welcome screen](../images/so-crates-welcome.png)

When you dismiss the welcome window, the main screen allows you to upload a file or load a previous analysis:

![Main screen](../images/so-crates-main.png)

After analysis, you can view network alerts, file alerts, network metadata, and extracted streams:

![Analysis screen](../images/so-crates-analysis.png)

Clicking a value in the data table opens a pivot menu for Include/Exclude/Only filtering, Hunt, and Correlate - which searches for every other log across the capture sharing that row's community ID (the cross-tool flow-correlation hash, computed by Suricata - force-enabled in 4.1.0):

![Pivot menu](../images/so-crates-pivot-menu.png)

Drilling into a Suricata, Sigma, or YARA alert shows an AI-generated summary of what the rule detects, when one is available for that rule. Suricata and Sigma alerts also show a Playbook with plain-English investigation guidance for that specific detection:

![Playbook](../images/so-crates-playbook.png)

You can optionally collapse the Playbook questions. You can also scroll to the bottom to see the ASCII transcript:

![ASCII transcript view](../images/so-crates-transcript.png)

You can also select the hexdump view:

![Hexdump view](../images/so-crates-hexdump.png)

To slice and dice your data, expand the Aggregation Tables section and click on values that you want to filter for:

![Aggregation table filtering](../images/so-crates-aggregation-filtering.png)
